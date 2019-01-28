package io.standardcore.security.binary;

import io.standardcore.security.BinaryConverter;

import java.util.Base64;

public class Base64BinaryConverter implements BinaryConverter {
    @Override
    public String getString(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    @Override
    public byte[] getBytes(String input) {
        return Base64.getDecoder().decode(input);
    }
}
