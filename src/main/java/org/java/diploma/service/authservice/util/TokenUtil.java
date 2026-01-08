package org.java.diploma.service.authservice.util;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
public final class TokenUtil {

    private static final SecureRandom RNG = new SecureRandom();
    private static final int TOKEN_BYTE_LENGTH = 48;
    private static final String HASH_ALGORITHM = "SHA-256";

    private static final String ERROR_HASH_FAILURE = "Hash failure";

    private static final String LOG_TOKEN_GENERATED = "Opaque token generated with {} bytes";
    private static final String LOG_HASH_CREATED = "SHA-256 hash created for input";
    private static final String LOG_HASH_FAILED = "Failed to create SHA-256 hash: {}";

    private TokenUtil() {}

    public static String newOpaqueToken() {
        byte[] bytes = new byte[TOKEN_BYTE_LENGTH];
        RNG.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        log.debug(LOG_TOKEN_GENERATED, TOKEN_BYTE_LENGTH);
        return token;
    }

    public static String sha256B64Url(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] dig = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(dig);
            log.debug(LOG_HASH_CREATED);
            return hash;
        } catch (NoSuchAlgorithmException e) {
            log.error(LOG_HASH_FAILED, e.getMessage());
            throw new IllegalStateException(ERROR_HASH_FAILURE, e);
        }
    }
}