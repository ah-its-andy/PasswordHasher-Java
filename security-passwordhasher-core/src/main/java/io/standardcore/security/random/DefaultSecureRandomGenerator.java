package io.standardcore.security.random;

import io.standardcore.security.PasswordHashException;
import io.standardcore.security.SecureRandomGenerator;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DefaultSecureRandomGenerator implements SecureRandomGenerator {
    @Override
    public byte[] generateBytes(int length) {
        byte[] bytes = new byte[length];
        getBytes(bytes, 0, length);
        return bytes;
    }

    private void getBytes(byte[] data, int offset, int count) {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] buffer = new byte[count];
            sr.nextBytes(buffer);
            System.arraycopy(buffer, 0, data, offset, count);
        }catch (NoSuchAlgorithmException e){
            throw  new PasswordHashException("SHA1PRNG", e);
        }
    }
}
