package PasswordHasherTest;

import io.standardcore.security.*;
import io.standardcore.security.binary.Base64BinaryConverter;
import io.standardcore.security.hasher.Aes256PasswordHasher;
import io.standardcore.security.hasher.Pbkdf2PasswordHasher;
import io.standardcore.security.random.DefaultSecureRandomGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class PasswordHasherTests {
    private final static String TEST_PASSWORD = "TestPassword1234567890!@#$%^*&(()(__)";
    private final static List<PasswordFormatHasher> passwordFormatHashers;
    private final static BinaryConverter binaryConverter = new Base64BinaryConverter();
    private final static SecureRandomGenerator secureRandomGenerator = new DefaultSecureRandomGenerator();

    static {
        passwordFormatHashers = new ArrayList<>();
        passwordFormatHashers.add(new Pbkdf2PasswordHasher());
        passwordFormatHashers.add(new Aes256PasswordHasher());
    }

    @Test
    public void Pbkdf2WthBase64() {
        PasswordHasher passwordHasher = new DefaultPasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
        String hashedPassword = passwordHasher.hashPassword(TEST_PASSWORD, FormatMarkerConsts.PBKDF2);
        boolean flag = passwordHasher.verifyHashedPassword(hashedPassword, TEST_PASSWORD);
        Assertions.assertTrue(flag);
    }

    @Test
    public void Aes256WithBase64() {
        Security.addProvider(new BouncyCastleProvider());
        PasswordHasher passwordHasher = new DefaultPasswordHasher(binaryConverter, secureRandomGenerator, passwordFormatHashers);
        String hashedPassword = passwordHasher.hashPassword(TEST_PASSWORD, FormatMarkerConsts.AES256);
        boolean flag = passwordHasher.verifyHashedPassword(hashedPassword, TEST_PASSWORD);
        Assertions.assertTrue(flag);
    }
}
