package io.standardcore.security;

import java.util.List;

public class DefaultPasswordHasher implements PasswordHasher {
    private final BinaryConverter binaryConverter;
    private final SecureRandomGenerator secureRandomGenerator;
    private final List<PasswordFormatHasher> passwordFormatHashers;

    public DefaultPasswordHasher(BinaryConverter binaryConverter, SecureRandomGenerator secureRandomGenerator, List<PasswordFormatHasher> passwordFormatHashers) {
        this.binaryConverter = binaryConverter;
        this.secureRandomGenerator = secureRandomGenerator;
        this.passwordFormatHashers = passwordFormatHashers;
    }

    @Override
    public String hashPassword(String password) {
        return hashPassword(password, FormatMarkerConsts.PBKDF2);
    }

    @Override
    public String hashPassword(String password, byte formatMarker) {
        byte[] hashedPassword = getPasswordFormatHasher(formatMarker).hashPassword(password, secureRandomGenerator);
        return binaryConverter.getString(hashedPassword);
    }

    @Override
    public boolean verifyHashedPassword(String hashedPassword, String providedPassword) {
        byte[] decodedHashedPassword = binaryConverter.getBytes(hashedPassword);
        byte formatMarker = decodedHashedPassword[0];
        return getPasswordFormatHasher(formatMarker).verifyHashedPassword(decodedHashedPassword, providedPassword);
    }

    private PasswordFormatHasher getPasswordFormatHasher(byte formatMarker)
    {
        PasswordFormatHasher passwordFormatHasher = passwordFormatHashers
                .stream().filter(x-> x.supported(formatMarker))
                .findFirst().orElse(null);
        if (passwordFormatHasher == null) throw new UnsupportedOperationException("Format marker " + formatMarker);
        return passwordFormatHasher;
    }
}
