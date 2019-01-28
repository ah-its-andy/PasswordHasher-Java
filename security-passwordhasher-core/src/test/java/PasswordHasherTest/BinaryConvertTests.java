package PasswordHasherTest;

import io.standardcore.security.BinaryConverter;
import io.standardcore.security.BufferUtil;
import io.standardcore.security.binary.Base64BinaryConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class BinaryConvertTests {
    private final static byte[] TEST_INPUT = "1234567890-=!@#$%^&*()_ASJKLFDJKLdsjakdjklasjkdla".getBytes(StandardCharsets.UTF_8);

    @Test
    public void Base64() {
        BinaryConverter converter = new Base64BinaryConverter();
        String str = converter.getString(TEST_INPUT);
        byte[] bytes = converter.getBytes(str);
        boolean flag = BufferUtil.byteArraysEqual(TEST_INPUT, bytes);
        Assertions.assertTrue(flag);
    }
}
