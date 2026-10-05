package com.reviewer.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

@Component
public class HmacVerifier {

    private static final String HMAC_SHA256 = "HmacSHA256";

    @Value("${github.webhook.secret:}")
    private String webhookSecret;

    public boolean isValidSignature(String payload, String signatureHeader) {
        // If no secret is configured in the environment, bypass validation (dev mode)
        if (webhookSecret == null || webhookSecret.isBlank()) {
            return true;
        }

        if (signatureHeader == null || !signatureHeader.startsWith("sha256=")) {
            return false;
        }

        try {
            String expectedHash = signatureHeader.substring("sha256=".length());

            Mac mac = Mac.getInstance(HMAC_SHA256);
            SecretKeySpec secretKey = new SecretKeySpec(webhookSecret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
            mac.init(secretKey);

            byte[] hmacBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            String computedHash = HexFormat.of().formatHex(hmacBytes);

            // Constant-time check to prevent timing attacks
            return MessageDigest.isEqual(
                computedHash.getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            System.err.println("HMAC verification error: " + e.getMessage());
            return false;
        }
    }
}
