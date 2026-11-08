package com.reviewer.engine;

import com.github.javaparser.StaticJavaParser;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FixValidator {

    private static final Pattern CODE_BLOCK_PATTERN = Pattern.compile("```(?:java)?\\s*([\\s\\S]*?)\\s*```", Pattern.CASE_INSENSITIVE);
    private static final Pattern COMMENTS = Pattern.compile("//[^\\n]*|/\\*[\\s\\S]*?\\*/");

    /** Pulls the code out of a ```java ... ``` block if the model wrapped it in markdown. */
    public static String cleanCode(String raw) {
        if (raw == null) return "";
        Matcher matcher = CODE_BLOCK_PATTERN.matcher(raw);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return raw.trim();
    }

    /** True only if the AI's answer contains real Java code that parses. */
    public static boolean isValidJavaSnippet(String code) {
        String sanitized = cleanCode(code);

        // An empty answer, or one that is only comments, is not a fix
        if (COMMENTS.matcher(sanitized).replaceAll("").isBlank()) {
            return false;
        }

        try {
            StaticJavaParser.parseStatement(sanitized);   // a single statement
            return true;
        } catch (Exception e1) {
            try {
                StaticJavaParser.parseBlock("{" + sanitized + "}");   // several statements
                return true;
            } catch (Exception e2) {
                try {
                    StaticJavaParser.parse(sanitized);   // whole classes
                    return true;
                } catch (Exception e3) {
                    try {
                        StaticJavaParser.parse("class TempWrapper { " + sanitized + " }");   // methods/fields
                        return true;
                    } catch (Exception e4) {
                        return false;
                    }
                }
            }
        }
    }
}
