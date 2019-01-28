package io.standardcore.security.hasher;

import io.standardcore.security.*;

import java.nio.charset.StandardCharsets;

public class Aes256PasswordHasher implements PasswordFormatHasher {
    public boolean supported(byte formatMarker) {
        return FormatMarkerConsts.AES256 == formatMarker;
    }

    public byte[] hashPassword(String password, SecureRandomGenerator secureRandomGenerator) {
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] salt = secureRandomGenerator.generateBytes(32);
        byte[] iv = secureRandomGenerator.generateBytes(16);

        Aes cipher = Aes.create(salt, iv);
        cipher.setKeySize(256);
        cipher.setPaddingMode(PaddingModeConsts.PKCS7);
        cipher.setCipherMode(CipherModeConsts.CBC);

        CryptoTransform encryptor = cipher.createEncryptor();
        byte[] subKey = encryptor.transformFinalBlock(passwordBytes, 0, passwordBytes.length);

        byte[] outputBytes = new byte[9 + salt.length + iv.length + subKey.length];
        outputBytes[0] = FormatMarkerConsts.AES256;
        BufferUtil.writeNetworkByteOrder(outputBytes, 1, cipher.getPaddingMode());
        BufferUtil.writeNetworkByteOrder(outputBytes, 5, cipher.getCipherMode());
        BufferUtil.blockFill(salt, outputBytes, 9);
        BufferUtil.blockFill(iv, outputBytes, 9 + salt.length);
        BufferUtil.blockFill(subKey, outputBytes, 9 + salt.length + iv.length);
        return outputBytes;
    }

    public boolean verifyHashedPassword(byte[] decodedHashedPassword, String providedPassword) {
        int paddingMode = BufferUtil.readNetworkByteOrder(decodedHashedPassword, 1);
        int cipherMode = BufferUtil.readNetworkByteOrder(decodedHashedPassword, 5);

        byte[] salt = new byte[32];
        BufferUtil.blockCopy(decodedHashedPassword, 9, salt, 0, salt.length);
        byte[] iv = new byte[16];
        BufferUtil.blockCopy(decodedHashedPassword, 9 + salt.length, iv, 0, iv.length);
        byte[] expectedKey = new byte[decodedHashedPassword.length - salt.length - iv.length - 9];
        BufferUtil.blockCopy(decodedHashedPassword, 9 + salt.length + iv.length, expectedKey, 0, expectedKey.length);

        Aes cipher = Aes.create(salt, iv);
        cipher.setKeySize(256);
        cipher.setPaddingMode(paddingMode);
        cipher.setCipherMode(cipherMode);

        CryptoTransform decryptor = cipher.createDecryptor();
        byte[] expectedPasswordBytes = decryptor.transformFinalBlock(expectedKey, 0, expectedKey.length);
        String expectedPassword = new String(expectedPasswordBytes, StandardCharsets.UTF_8);
        return providedPassword.equals(expectedPassword);
    }
}
