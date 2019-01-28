package io.standardcore.security;

public class KeyDerivationPrfConst {
    public final static int HMACSHA1 = 0;
    public final static int HMACSHA256 = 1;
    public final static int HMACSHA512= 2;

    public final static String getName(int prf){
        if(prf == HMACSHA1) return "PBKDF2WithHmacSHA1";
        if(prf == HMACSHA256) return "PBKDF2WithHmacSHA256";
        if(prf == HMACSHA512) return "PBKDF2WithHmacSHA512";
        return "KeyDerivationPrf_NOT_FOUND";
    }
}
