package com.reviewer.cli;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.reviewer.model.Finding;
import com.reviewer.visitors.HardcodedSecretVisitor;
import com.reviewer.visitors.SqlInjectionVisitor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Scans a folder of Java source files with the AST rules and prints what it finds.
 * No LLM and no network are needed, so it can run in CI.
 *
 * Usage: ScanCli <path> [--include-tests] [--no-fail] [--github]
 *   --include-tests  also scan files under src/test (skipped by default: test code is full of fake secrets)
 *   --no-fail        always exit 0, even when there are findings
 *   --github         print GitHub Actions annotations so findings show up on the pull request
 *
 * Exit code: 0 = clean, 1 = findings, 2 = bad usage.
 */
public class ScanCli {

    /** One finding plus the file it came from. */
    public record FileFinding(Path file, Finding finding) {}

    /** What a scan produced: the findings, plus counts for the summary line. */
    public record ScanResult(List<FileFinding> findings, int filesScanned, int filesSkipped) {}

    public static void main(String[] args) {
        if (args.length == 0 || args[0].startsWith("--")) {
            System.err.println("Usage: ScanCli <path> [--include-tests] [--no-fail] [--github]");
            System.exit(2);
        }
        Path root = Path.of(args[0]);
        List<String> flags = List.of(args).subList(1, args.length);
        boolean includeTests = flags.contains("--include-tests");
        boolean noFail = flags.contains("--no-fail");
        boolean github = flags.contains("--github") || "true".equals(System.getenv("GITHUB_ACTIONS"));

        if (!Files.exists(root)) {
            System.err.println("Path not found: " + root);
            System.exit(2);
        }

        ScanResult result;
        try {
            result = scan(root, includeTests);
        } catch (IOException e) {
            System.err.println("Could not read " + root + ": " + e.getMessage());
            System.exit(2);
            return;
        }

        for (FileFinding ff : result.findings()) {
            Finding f = ff.finding();
            Path shown = relativize(root, ff.file());
            System.out.printf("%s:%d  [%s] %s%n    %s%n", shown, f.lineNumber(), f.ruleName(), f.message(),
                    firstLine(f.codeSnippet()));
            if (github) {
                // GitHub turns this line into an annotation on the file and line in the PR
                System.out.printf("::error file=%s,line=%d,title=%s::%s%n",
                        shown, f.lineNumber(), f.ruleName(), escape(f.message()));
            }
        }

        System.out.printf("%nScanned %d Java file(s), skipped %d that could not be parsed. %d finding(s).%n",
                result.filesScanned(), result.filesSkipped(), result.findings().size());

        if (!result.findings().isEmpty() && !noFail) System.exit(1);
    }

    /** Scans one file or every .java file under a folder. */
    public static ScanResult scan(Path root, boolean includeTests) throws IOException {
        // Parse with the newest language level so modern syntax (records, switch patterns) is accepted
        StaticJavaParser.getParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.BLEEDING_EDGE);

        List<Path> files;
        try (Stream<Path> walk = Files.walk(root)) {
            files = walk.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> includeTests || !isTestFile(root, p))
                    .sorted()
                    .toList();
        }

        List<FileFinding> all = new ArrayList<>();
        int scanned = 0, skipped = 0;
        for (Path file : files) {
            CompilationUnit cu;
            try {
                cu = StaticJavaParser.parse(file);
            } catch (Exception e) {
                skipped++;            // not valid Java (templates, broken files): skip, don't crash
                continue;
            }
            scanned++;
            List<Finding> findings = new ArrayList<>();
            cu.accept(new SqlInjectionVisitor(), findings);
            cu.accept(new HardcodedSecretVisitor(), findings);
            for (Finding f : findings) all.add(new FileFinding(file, f));
        }
        return new ScanResult(all, scanned, skipped);
    }

    private static boolean isTestFile(Path root, Path file) {
        String rel = relativize(root, file).toString().replace('\\', '/');
        return rel.contains("src/test/") || rel.startsWith("test/") || rel.contains("/test/");
    }

    private static Path relativize(Path root, Path file) {
        return Files.isDirectory(root) ? root.relativize(file) : file.getFileName();
    }

    private static String firstLine(String code) {
        String line = code.strip().lines().findFirst().orElse("");
        return line.length() > 160 ? line.substring(0, 157) + "..." : line;
    }

    /** GitHub annotation messages need %, CR and LF escaped. */
    private static String escape(String s) {
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A");
    }
}
