package com.reviewer.engine;

import com.github.javaparser.StaticJavaParser;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FixValidator {

    private static final Pattern CODE_BLOCK_PATTERN = Pattern.compile("```(?:java)?\\s*([\\s\\S]*?)\\s*```", Pattern.CASE_INSENSITIVE);

    public static String cleanCode(String raw) {
        if (raw == null) return "";
        Matcher matcher = CODE_BLOCK_PATTERN.matcher(raw);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return raw.trim();
    }

    public static boolean isValidJavaSnippet(String code) {
        String sanitized = cleanCode(code);
        try {
            StaticJavaParser.parseStatement(sanitized);
            return true;
        } catch (Exception e1) {
            try {
                StaticJavaParser.parseBlock("{" + sanitized + "}");
                return true;
            } catch (Exception e2) {
                try {
                    StaticJavaParser.parse("class TempWrapper { void wrappedMethod() { " + sanitized + " } }");
                    return true;
                } catch (Exception e3) {
                    return false;
                }
            }
        }
    }
}
