package io.standardcore.security.hasher;

import io.standardcore.security.*;

public class Pbkdf2PasswordHasher implements PasswordFormatHasher {
    private final static int MIN_ITER_COUNT = 10000;
    private final Pbkdf2Provider pbkdf2Provider;

    public Pbkdf2PasswordHasher(Pbkdf2Provider pbkdf2Provider) {
        this.pbkdf2Provider = pbkdf2Provider;
    }

    public Pbkdf2PasswordHasher(){
        this(new ManagedPbkdf2Provider());
    }

    @Override
    public boolean supported(byte formatMarker) {
        return FormatMarkerConsts.PBKDF2 == formatMarker;
    }

    @Override
    public byte[] hashPassword(String password, SecureRandomGenerator secureRandomGenerator) {
        return hashPassword(password, pbkdf2Provider, secureRandomGenerator, KeyDerivationPrfConst.HMACSHA256, MIN_ITER_COUNT,
                128 / 8,
                256 / 8);
    }

    @Override
    public boolean verifyHashedPassword(byte[] decodedHashedPassword, String providedPassword) {
        int prf = BufferUtil.readNetworkByteOrder(decodedHashedPassword, 1);
        int iterCount = BufferUtil.readNetworkByteOrder(decodedHashedPassword, 5);
        int saltLength = BufferUtil.readNetworkByteOrder(decodedHashedPassword, 9);
        // Read the salt: must be >= 128 bits
        if (saltLength < 128 / 8)
            return false;

        byte[] salt = new byte[saltLength];
        System.arraycopy(decodedHashedPassword, 13, salt, 0, salt.length);
        // Read the subkey (the rest of the payload): must be >= 128 bits
        int subkeyLength = decodedHashedPassword.length - 13 - salt.length;
        if (subkeyLength < 128 / 8)
            return false;
        byte[] expectedSubkey = new byte[subkeyLength];
        System.arraycopy(decodedHashedPassword, 13 + salt.length, expectedSubkey, 0, expectedSubkey.length);

        // Hash the incoming password and verify it
        byte[] actualSubkey = pbkdf2Provider.deriveKey(providedPassword, salt, prf, iterCount, subkeyLength);

        return iterCount > 0 && BufferUtil.byteArraysEqual(expectedSubkey, actualSubkey);
    }

    private byte[] hashPassword(String password, Pbkdf2Provider pbkdf2Provider, SecureRandomGenerator secureRandomGenerator, int keyDerivationPrfConst, int iterCount, int saltSize, int numBytesRequested) {
        int actIterCount = iterCount;
        if(actIterCount < MIN_ITER_COUNT) actIterCount = MIN_ITER_COUNT;
        byte[] salt = secureRandomGenerator.generateBytes(saltSize);
        byte[] subKey = pbkdf2Provider.deriveKey(password, salt, keyDerivationPrfConst, actIterCount, numBytesRequested);
        byte[] outputBytes = new byte[13+salt.length+subKey.length];
        outputBytes[0] = 0x01; // format marker
        BufferUtil.writeNetworkByteOrder(outputBytes, 1, keyDerivationPrfConst);
        BufferUtil.writeNetworkByteOrder(outputBytes, 5,  actIterCount);
        BufferUtil.writeNetworkByteOrder(outputBytes, 9,  saltSize);
        System.arraycopy(salt, 0, outputBytes, 13, salt.length);
        System.arraycopy(subKey, 0, outputBytes, 13 + saltSize, subKey.length);
        return outputBytes;
    }
}
