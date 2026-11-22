package com.reviewer;

import com.reviewer.cli.ScanCli;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class ScanCliTest {

    private static final String VULNERABLE =
        "import java.sql.*;\n"
      + "class Bad {\n"
      + "  void run(Statement stmt, String userInput) throws Exception {\n"
      + "    String apiKey = \"sk-live-123456\";\n"
      + "    stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + userInput + \"'\");\n"
      + "  }\n"
      + "}\n";

    private static final String CLEAN =
        "class Good {\n"
      + "  int add(int a, int b) { return a + b; }\n"
      + "}\n";

    private static void write(Path dir, String name, String content) throws Exception {
        Path file = dir.resolve(name);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    @Test void scan_FindsBothRulesInAFolder(@TempDir Path dir) throws Exception {
        write(dir, "src/main/java/Bad.java", VULNERABLE);
        write(dir, "src/main/java/Good.java", CLEAN);

        ScanCli.ScanResult result = ScanCli.scan(dir, false);

        assertEquals(2, result.filesScanned());
        assertEquals(2, result.findings().size());
        assertTrue(result.findings().stream().anyMatch(f -> f.finding().ruleName().equals("SQL_INJECTION_RISK")));
        assertTrue(result.findings().stream().anyMatch(f -> f.finding().ruleName().equals("HARDCODED_SECRET")));
        assertTrue(result.findings().stream().allMatch(f -> f.file().endsWith("Bad.java")));
    }

    @Test void scan_CleanFolder_NoFindings(@TempDir Path dir) throws Exception {
        write(dir, "Good.java", CLEAN);

        ScanCli.ScanResult result = ScanCli.scan(dir, false);

        assertEquals(1, result.filesScanned());
        assertTrue(result.findings().isEmpty());
    }

    @Test void scan_SkipsTestFoldersByDefault(@TempDir Path dir) throws Exception {
        write(dir, "src/test/java/BadTest.java", VULNERABLE);

        assertTrue(ScanCli.scan(dir, false).findings().isEmpty());
        assertEquals(2, ScanCli.scan(dir, true).findings().size());
    }

    @Test void scan_SkipsFilesThatAreNotValidJava(@TempDir Path dir) throws Exception {
        write(dir, "Broken.java", "this is not java {{{");
        write(dir, "Bad.java", VULNERABLE);

        ScanCli.ScanResult result = ScanCli.scan(dir, false);

        assertEquals(1, result.filesSkipped());
        assertEquals(1, result.filesScanned());
        assertEquals(2, result.findings().size());
    }

    @Test void scan_IgnoresNonJavaFiles(@TempDir Path dir) throws Exception {
        write(dir, "notes.txt", "String password = \"hunter2\";");

        ScanCli.ScanResult result = ScanCli.scan(dir, false);

        assertEquals(0, result.filesScanned());
        assertTrue(result.findings().isEmpty());
    }

    @Test void scan_AcceptsASingleFile(@TempDir Path dir) throws Exception {
        write(dir, "Bad.java", VULNERABLE);

        ScanCli.ScanResult result = ScanCli.scan(dir.resolve("Bad.java"), false);

        assertEquals(2, result.findings().size());
    }
}
