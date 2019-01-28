package io.standardcore.security;

public interface PasswordHasher {
    String hashPassword(String password);
    String hashPassword(String password, byte formatMarker);

    boolean verifyHashedPassword(String hashedPassword, String providedPassword);
}
