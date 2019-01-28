package io.standardcore.security;

public interface Pbkdf2Provider {
    byte[] deriveKey(String password, byte[] salt, int keyDerivationPrfConst, int iterationCount, int numBytesRequested);
}
