package io.standardcore.security;

public interface KeyedHashAlgorithm {
    byte[] computeHash(byte[] buffer);
}
