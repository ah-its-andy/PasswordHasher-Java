package io.standardcore.security;

public interface PasswordFormatHasher {
    boolean supported(byte formatMarker);

    byte[] hashPassword(String password, SecureRandomGenerator secureRandomGenerator);
    boolean verifyHashedPassword(byte[] decodedHashedPassword, String providedPassword);
}
