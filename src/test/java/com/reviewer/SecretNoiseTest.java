package com.reviewer;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.reviewer.model.Finding;
import com.reviewer.visitors.HardcodedSecretVisitor;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * False alarms found by scanning 31 open-source projects, and the real secrets
 * that must still be reported after filtering them out.
 */
public class SecretNoiseTest {

    private static List<Finding> scan(String classBody) {
        CompilationUnit cu = StaticJavaParser.parse("class Config {\n" + classBody + "\n}");
        List<Finding> findings = new ArrayList<>();
        new HardcodedSecretVisitor().visit(cu, findings);
        return findings;
    }

    // ---------- names of secrets, not secrets ----------

    @Test void configKeyConstant_NoFinding() {
        assertTrue(scan("static final String PASSWORD_KEY = \"password\";").isEmpty());
        assertTrue(scan("static final String PROP_PASSWORD = \"password\";").isEmpty());
    }

    @Test void dottedConfigKey_NoFinding() {
        assertTrue(scan("static final String SSL_KEY_PASSWORD_CONFIG = \"ssl.key.password\";").isEmpty());
        assertTrue(scan("static final String JAVA_NET_SOCKS_PASSWORD = \"java.net.socks.password\";").isEmpty());
    }

    @Test void headerName_NoFinding() {
        assertTrue(scan("static final String TOKEN_HEADER = \"X-Auth-Token\";").isEmpty());
    }

    @Test void errorMessage_NoFinding() {
        assertTrue(scan("String passwordMustNotBeEmptyMsg = \"Password must not be empty\";").isEmpty());
    }

    @Test void filePath_NoFinding() {
        assertTrue(scan("static final String SERVER_PRIVATE_KEY_PATH = \"/etc/ssl/server.key\";").isEmpty());
    }

    @Test void placeholder_NoFinding() {
        assertTrue(scan("String dbPassword = \"${DB_PASSWORD}\";").isEmpty());
        assertTrue(scan("String password = \"****\";").isEmpty());
    }

    // ---------- real secrets must still be reported ----------

    @Test void defaultPassword_StillFlagged() {
        assertEquals(1, scan("static final String DEFAULT_PASSWORD = \"changeme\";").size());
    }

    @Test void weakLiteralPassword_StillFlagged() {
        assertEquals(1, scan("String password = \"admin\";").size());
        assertEquals(1, scan("String password = \"password\";").size());
    }

    @Test void apiKeyConstant_StillFlagged() {
        assertEquals(1, scan("static final String API_KEY = \"AbCdEf123456\";").size());
        assertEquals(1, scan("static final String SECRET_KEY = \"9f8a7b6c5d4e\";").size());
    }

    @Test void jwtToken_StillFlagged() {
        assertEquals(1, scan("String authToken = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + "eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\";").size());
    }

    @Test void awsKeyInConfigNamedVariable_StillFlagged() {
        // The value alone looks like an AWS key, so the variable name cannot excuse it
        assertEquals(1, scan("String keyIdProperty = \"" + "AKIA" + "ABCDEFGHIJKLMNOP" + "\";").size());
    }
}
