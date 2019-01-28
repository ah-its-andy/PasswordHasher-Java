package io.standardcore.security;

public class ManagedPbkdf2Provider implements Pbkdf2Provider {
    public byte[] deriveKey(String password, byte[] salt, int keyDerivationPrfConst, int iterationCount, int numBytesRequested)
    {
        byte[] numArray = new byte[numBytesRequested];
        int dstOffset = 0;
        int val1 = numBytesRequested;
        byte[] buffer = new byte[salt.length + 4];
        System.arraycopy(salt, 0,  buffer, 0, salt.length);
        KeyedHashAlgorithm managedHmacAlgorithm = ManagedPbkdf2Provider.prfToManagedHmacAlgorithm(keyDerivationPrfConst, password);

        int num=1;
        while (val1 > 0){
            buffer[buffer.length - 4] = (byte) (num >> 24);
            buffer[buffer.length - 3] = (byte) (num >> 16);
            buffer[buffer.length - 2] = (byte) (num >> 8);
            buffer[buffer.length - 1] = (byte) num;
            byte[] hash = managedHmacAlgorithm.computeHash(buffer);
            byte[] dest = hash;
            for (int index = 1; index < iterationCount; ++index)
            {
                hash = managedHmacAlgorithm.computeHash(hash);
                ManagedPbkdf2Provider.XorBuffers(hash, dest);
            }
            int count = Math.min(val1, dest.length);
            System.arraycopy(dest, 0, numArray, dstOffset, count);
            dstOffset += count;
            val1 -= count;
            ++num;
        }

        return numArray;
    }

    private final static KeyedHashAlgorithm prfToManagedHmacAlgorithm(int keyDerivationPrfConst, String password){
        byte[] bytes = password.getBytes();
        try
        {
            switch (keyDerivationPrfConst)
            {
                case KeyDerivationPrfConst.HMACSHA1:
                    return new HmacSha1(bytes);
                case KeyDerivationPrfConst.HMACSHA256:
                    return new HmacSha256(bytes);
                case KeyDerivationPrfConst.HMACSHA512:
                    return new HmacSha512(bytes);
                default:
                    throw new PasswordHashException("系统没有提供推演算法("+ KeyDerivationPrfConst.getName(keyDerivationPrfConst) +")");
            }
        }
        finally
        {
            bytes = null;
        }
    }

    private static void XorBuffers(byte[] src, byte[] dest)
    {
        for (int index = 0; index < src.length; ++index)
            dest[index] ^= src[index];
    }
}
