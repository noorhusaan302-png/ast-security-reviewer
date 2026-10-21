package com.reviewer.model;

public record Finding(
    String ruleName,
    String severity,
    int lineNumber,
    String message,
    String codeSnippet
) {
    @Override
    public String toString() {
        return String.format("[%s] Line %d (%s): %s\n--> Code: %s\n",
                severity, lineNumber, ruleName, message, codeSnippet.trim());
    }
}
