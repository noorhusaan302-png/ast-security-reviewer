package com.reviewer.engine;

import com.github.javaparser.StaticJavaParser;

public class FixValidator {

    public static boolean isValidJavaSnippet(String snippet) {
        String cleanSnippet = cleanCode(snippet);

        // Test 1: Can it be parsed as a statement? (e.g. stmt.executeQuery(...);)
        try {
            StaticJavaParser.parseStatement(cleanSnippet);
            return true;
        } catch (Exception ignored) {}

        // Test 2: Can it be parsed as a body declaration / method / field?
        try {
            StaticJavaParser.parseBodyDeclaration(cleanSnippet);
            return true;
        } catch (Exception ignored) {}

        // Test 3: Can it be parsed inside a dummy method wrapper?
        try {
            StaticJavaParser.parseStatement("{" + cleanSnippet + "}");
            return true;
        } catch (Exception ignored) {}

        return false;
    }

    public static String cleanCode(String raw) {
        // Strip markdown fences if the LLM outputted them despite prompt instructions
        return raw.replaceAll("```java", "")
                  .replaceAll("```", "")
                  .trim();
    }
}
