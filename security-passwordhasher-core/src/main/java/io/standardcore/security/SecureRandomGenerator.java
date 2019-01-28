package io.standardcore.security;

public interface SecureRandomGenerator {
    byte[] generateBytes(int length);
}
