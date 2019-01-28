package PasswordHasherTest;

import io.standardcore.security.PasswordFormatHasher;
import io.standardcore.security.hasher.Aes256PasswordHasher;
import io.standardcore.security.hasher.Pbkdf2PasswordHasher;
import io.standardcore.security.random.DefaultSecureRandomGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Security;

public class PasswordFormatHasherTests {
    private final static String TEST_PASSWORD = "TestPassword1234567890!@#$%^*&(()(__)";

    @Test
    public void pbkdf2() {
        PasswordFormatHasher hasher = new Pbkdf2PasswordHasher();
        byte[] hashedPassword = hasher.hashPassword(TEST_PASSWORD, new DefaultSecureRandomGenerator());
        Assertions.assertNotNull(hashedPassword);
        boolean flag = hasher.verifyHashedPassword(hashedPassword, TEST_PASSWORD);
        Assertions.assertTrue(flag);
    }

    @Test
    public void aes256() {
        Security.addProvider(new BouncyCastleProvider());
        PasswordFormatHasher hasher = new Aes256PasswordHasher();
        byte[] hashedPassword = hasher.hashPassword(TEST_PASSWORD, new DefaultSecureRandomGenerator());
        Assertions.assertNotNull(hashedPassword);
        boolean flag = hasher.verifyHashedPassword(hashedPassword, TEST_PASSWORD);
        Assertions.assertTrue(flag);
    }
}
