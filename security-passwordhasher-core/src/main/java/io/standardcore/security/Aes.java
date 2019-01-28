package io.standardcore.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Aes {
    private  final static Map<Integer, String> PADDING_MAPPINGS;
    private  final static Map<Integer, String> CIPHERED_MAPPING;

    static {
        Map<Integer, String> paddingModeMappings = new HashMap<Integer, String>();
        paddingModeMappings.put(PaddingModeConsts.PKCS7, "PKCS7Padding");
        PADDING_MAPPINGS = Collections.unmodifiableMap(paddingModeMappings);
        Map<Integer, String> cipherModeMappings = new HashMap<Integer, String>();
        cipherModeMappings.put(CipherModeConsts.CBC, "CBC");
        CIPHERED_MAPPING = Collections.unmodifiableMap(cipherModeMappings);
    }

    private static String getAesDesc(int paddingMode, int cipherMode){
        if(!CIPHERED_MAPPING.containsKey(cipherMode)) {
            throw new BlockTransformException("BadCipherMode" + cipherMode);
        }
        if(!PADDING_MAPPINGS.containsKey(paddingMode)) {
            throw new BlockTransformException("BadPaddingMode" + cipherMode);
        }
        StringBuilder builder = new StringBuilder();
        builder.append("AES/");
        builder.append(CIPHERED_MAPPING.get(cipherMode));
        builder.append("/");
        builder.append(PADDING_MAPPINGS.get(paddingMode));
        return builder.toString();
    }


    private int keySize;
    private int paddingMode;
    private int cipherMode;
    private byte[] key;
    private byte[] iv;

    private Aes(int keySize, int paddingMode, int cipherMode, byte[] key, byte[] iv) {
        this.keySize = keySize;
        this.paddingMode = paddingMode;
        this.cipherMode = cipherMode;
        this.key = key;
        this.iv = iv;
    }

    public static Aes create(int paddingMode, int cipherMode, byte[] key, int keySize, byte[] iv){
        return new Aes(keySize, paddingMode, cipherMode, key, iv);
    }

    public static Aes create(byte[] key, byte[] iv){
        return new Aes(key.length * 8, PaddingModeConsts.PKCS7, CipherModeConsts.CBC, key, iv);
    }


    private Cipher createCipher(boolean encryptMode){
        try {
            String aesDesc = getAesDesc(paddingMode, cipherMode);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(encryptMode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);
            return cipher;
        } catch (NoSuchAlgorithmException e) {
            throw new BlockTransformException("NoSuchAlgorithmException", e);
        } catch (NoSuchPaddingException e) {
            throw new BlockTransformException("NoSuchPaddingException", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new BlockTransformException("InvalidAlgorithmParameterException", e);
        } catch (InvalidKeyException e) {
            throw new BlockTransformException("InvalidKeyException", e);
        }
    }

    public CryptoTransform createEncryptor(){
        return new Transformer(createCipher(true));
    }

    public CryptoTransform createDecryptor(){
        return new Transformer(createCipher(false));
    }

    public class Transformer implements CryptoTransform {
        private final Cipher cipher;

        public Transformer(Cipher cipher) {
            this.cipher = cipher;
        }

        public byte[] transformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount) {
            try {
                return cipher.doFinal(inputBuffer, inputOffset, inputCount);
            } catch (IllegalBlockSizeException e) {
                throw new BlockTransformException("IllegalBlockSizeException", e);
            } catch (BadPaddingException e) {
                throw new BlockTransformException("BadPaddingException", e);
            }
        }
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public int getPaddingMode() {
        return paddingMode;
    }

    public void setPaddingMode(int paddingMode) {
        this.paddingMode = paddingMode;
    }

    public int getCipherMode() {
        return cipherMode;
    }

    public void setCipherMode(int cipherMode) {
        this.cipherMode = cipherMode;
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }
}
