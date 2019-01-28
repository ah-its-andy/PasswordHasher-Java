package io.standardcore.security;

public interface BinaryConverter {
    String getString(byte[] input);
    byte[] getBytes(String input);
}
