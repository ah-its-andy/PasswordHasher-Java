package io.standardcore.security;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HmacSha256 implements KeyedHashAlgorithm {
    private static final String MAC_NAME = "HmacSHA256";

    private final SecretKey secretKey;

    public HmacSha256(byte[] password){
        secretKey = new SecretKeySpec(password, MAC_NAME);
    }

    @Override
    public byte[] computeHash(byte[] buffer) {
        return HmacFactory.getInstance(MAC_NAME, secretKey).doFinal(buffer);
    }
}
