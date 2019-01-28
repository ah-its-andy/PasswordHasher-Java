package io.standardcore.security;


import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HmacFactory {
    public final static Mac getInstance(String algorithm, SecretKey secretKey){
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKey);
            return mac;
        } catch (NoSuchAlgorithmException e){
            throw new PasswordHashException("Unsupported algorithm " +  algorithm, e);
        } catch (InvalidKeyException e){
            throw new PasswordHashException(e);
        }
    }
}
