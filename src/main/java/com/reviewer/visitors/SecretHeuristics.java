package com.reviewer.visitors;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Decides whether a string assigned to a secret-sounding variable is a real secret
 * or just the NAME of one.
 *
 * A survey of 31 open-source projects showed most false alarms were constants like
 *   PASSWORD_KEY = "password"            (a config key)
 *   SSL_KEY_PASSWORD_CONFIG = "ssl.key.password"
 *   TOKEN_HEADER = "X-Auth-Token"
 *   passwordEmptyMsg = "Password must not be empty"
 * None of those leak anything. This class filters them out.
 */
public final class SecretHeuristics {

    private SecretHeuristics() {}

    /** Words in a variable name that say "this holds a name, path or message", not the secret itself. */
    private static final Set<String> NAME_HINTS = Set.of(
        "prop", "property", "properties", "config", "conf", "cfg", "param", "params", "parameter",
        "name", "field", "header", "attr", "attribute", "prefix", "suffix", "doc", "docs",
        "msg", "message", "path", "file", "filename", "location", "dir", "env", "var",
        "option", "opt", "label", "type", "alias", "description", "desc", "placeholder",
        "pattern", "regex", "regexp", "format", "url", "uri", "endpoint", "callback", "handler",
        "class", "provider", "factory", "length", "len", "size", "count", "timeout", "expiry",
        "expiration", "ttl", "algorithm", "algo", "mechanism", "scheme", "column", "col", "table",
        "tag", "element", "node", "command", "cmd", "flag", "arg", "args", "error", "exception",
        "warning", "text", "title", "hint", "help", "usage", "mode", "policy", "strategy",
        "validator", "encoder", "decoder", "generator", "parser", "tokenizer", "id", "index", "idx",
        "display", "prompt", "mask", "rule", "validation", "required", "enabled", "disabled",
        "min", "max", "strength", "expired", "reset", "mismatch", "invalid", "missing"
    );

    /** "PASSWORD_KEY" is a config key, but "API_KEY" and "SECRET_KEY" are real secrets. */
    private static final Set<String> KEY_NAME_OWNERS = Set.of(
        "password", "passwd", "pwd", "token", "credential", "credentials"
    );

    private static final List<String> SECRET_WORDS = List.of(
        "password", "passwd", "secret", "apikey", "token", "accesskey", "privatekey", "credential"
    );

    private static final Set<String> NON_VALUES = Set.of("null", "true", "false", "none", "undefined");

    private static final Pattern LETTERS_AND_SEPARATORS = Pattern.compile("^[A-Za-z._\\-:/]+$");
    private static final Pattern KEY_SEGMENT = Pattern.compile("^[A-Za-z][A-Za-z0-9_\\-]{0,23}$");

    /**
     * True when the value is very unlikely to be a credential, so the finding should be dropped.
     * Only call this for variables flagged because of their NAME. Values that look like keys
     * on their own (AWS key IDs, PEM blocks) are always reported.
     */
    public static boolean looksLikeNameNotSecret(String varName, String value) {
        if (value == null || varName == null) return false;

        // 1. Placeholders that get filled in later: "${DB_PASSWORD}", "{{token}}", "<password>", "****"
        if (isPlaceholder(value)) return true;

        // 1b. Delimiters, literal words and regular expressions
        if (isSymbolOrPattern(value)) return true;

        // 2. Sentences: error messages, descriptions, prompts
        if (value.strip().contains(" ")) return true;

        // 3. The variable name says it holds a key name, path, header, message...
        List<String> nameTokens = splitName(varName);
        for (String token : nameTokens) {
            if (NAME_HINTS.contains(token)) return true;
        }
        int last = nameTokens.size() - 1;
        if (last >= 1 && nameTokens.get(last).equals("key")
                && KEY_NAME_OWNERS.contains(nameTokens.get(last - 1))) {
            return true;
        }

        // 4. Dotted config keys: "ssl.key.password", "oauth2.client.secret"
        if (isDottedKey(value)) return true;

        // 5. Letters-only values that contain a secret word: "password", "X-Auth-Token", "client_secret".
        //    That is the name of a credential. Exception: a non-constant like  password = "password"
        //    is a weak default password, so keep reporting it.
        if (LETTERS_AND_SEPARATORS.matcher(value).matches() && containsSecretWord(value)) {
            boolean exactWord = SECRET_WORDS.contains(value.toLowerCase());
            boolean constant = isConstantName(varName);
            boolean isDefault = nameTokens.contains("default");
            if (isDefault) return false;
            return constant || !exactWord;
        }

        return false;
    }

    private static boolean isPlaceholder(String value) {
        String v = value.strip();
        if (v.contains("${") || v.contains("#{") || v.contains("{{") || v.contains("%s")) return true;
        if (v.length() >= 2 && v.startsWith("<") && v.endsWith(">")) return true;
        // "****", "xxxx", "...." : one character repeated
        if (v.length() >= 3 && v.chars().distinct().count() == 1) return true;
        // "{0}", "%pid" : format arguments
        if (v.matches("\\{\\d+\\}") || v.startsWith("%")) return true;
        return false;
    }

    /** Parser tokens, flags and regexes: "$", ":", "=?", "null", "false", "(?i)password=[^;]*" */
    private static boolean isSymbolOrPattern(String value) {
        String v = value.strip();
        if (v.chars().noneMatch(Character::isLetterOrDigit)) return true;       // punctuation only
        if (NON_VALUES.contains(v.toLowerCase())) return true;
        return v.startsWith("(?") || v.contains("(.*") || v.contains(".*?") || v.contains("[^")
                || v.contains("\\");
    }

    private static boolean isDottedKey(String value) {
        if (!value.contains(".")) return false;
        String[] segments = value.split("\\.", -1);
        if (segments.length < 2) return false;
        int digits = 0;
        for (String segment : segments) {
            if (!KEY_SEGMENT.matcher(segment).matches()) return false;
            for (int i = 0; i < segment.length(); i++) {
                if (Character.isDigit(segment.charAt(i))) digits++;
            }
        }
        return digits <= 3;   // real tokens (JWTs) are long and full of digits
    }

    private static boolean containsSecretWord(String value) {
        String squashed = value.toLowerCase().replaceAll("[^a-z]", "");
        for (String word : SECRET_WORDS) {
            if (squashed.contains(word)) return true;
        }
        return false;
    }

    /** UPPER_SNAKE_CASE names are constants. */
    private static boolean isConstantName(String name) {
        return name.equals(name.toUpperCase()) && name.chars().anyMatch(Character::isLetter);
    }

    /** "sslKeyPassword_CONFIG" -> [ssl, key, password, config] */
    static List<String> splitName(String name) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean boundary = false;
            if (c == '_' || c == '$') {
                boundary = true;
            } else if (Character.isUpperCase(c) && current.length() > 0) {
                char prev = name.charAt(i - 1);
                boolean nextIsLower = i + 1 < name.length() && Character.isLowerCase(name.charAt(i + 1));
                // "keyPassword" splits before P; "SSLKey" splits before K
                if (Character.isLowerCase(prev) || Character.isDigit(prev)
                        || (Character.isUpperCase(prev) && nextIsLower)) {
                    boundary = true;
                }
            }
            if (boundary && current.length() > 0) {
                tokens.add(current.toString().toLowerCase());
                current.setLength(0);
            }
            if (c != '_' && c != '$') current.append(c);
        }
        if (current.length() > 0) tokens.add(current.toString().toLowerCase());
        return tokens;
    }
}
