package org.openhab.binding.mideaac.internal.security;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityUtil {

    private SecretKeySpec encKey = null;
    private final CloudProvider cloudProvider;
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    public SecurityUtil(CloudProvider cloudProvider) {
        this.cloudProvider = cloudProvider;
    }

    public SecretKeySpec getEncKey() throws NoSuchAlgorithmException {
        if (encKey == null) {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(cloudProvider.getSignKey().getBytes(StandardCharsets.US_ASCII));
            byte[] key = md.digest();
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            encKey = skeySpec;
        }

        return encKey;
    }

    public byte[] aes_decrypt(byte[] encrypt_data) {
        byte[] plainText = {};

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec key = getEncKey();

            try {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } catch (InvalidKeyException e) {
                logger.warn("AES decryption error: InvalidKeyException: {}", e.getMessage());
                return null;
            }

            try {
                plainText = cipher.doFinal(encrypt_data);
            } catch (IllegalBlockSizeException e) {
                logger.warn("AES decryption error: IllegalBlockSizeException: {}", e.getMessage());
                return null;
            } catch (BadPaddingException e) {
                logger.warn("AES decryption error: BadPaddingException: {}", e.getMessage());
                return null;
            }

        } catch (NoSuchAlgorithmException e) {
            logger.warn("AES decryption error: NoSuchAlgorithmException: {}", e.getMessage());
            return null;
        } catch (NoSuchPaddingException e) {
            logger.warn("AES decryption error: NoSuchPaddingException: {}", e.getMessage());
            return null;
        }

        return plainText;
    }
}
