package com.dutertry.htunnel.common.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Test;


public class CryptoUtilsTest {
    @Test
    public void testEncryption() throws GeneralSecurityException {
        SecretKey key = CryptoUtils.generateAESKey();
        
        String s = "Hello World";
        byte[] encrypted = CryptoUtils.encryptAES(s.getBytes(), key);
        
        String encodedKey = CryptoUtils.encodeAESKey(key);
        key = CryptoUtils.decodeAESKey(encodedKey);
        byte[] decrypted = CryptoUtils.decryptAES(encrypted, key);
        
        Assert.assertEquals(s, new String(decrypted));  
    }
    
    @Test
    public void testRSASignature() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair keyPair = generator.generateKeyPair();
        
        byte[] data = "Hello World".getBytes();
        String signature = CryptoUtils.signRSA(data, keyPair.getPrivate());
        
        Assert.assertTrue(CryptoUtils.verifyRSA(data, signature, keyPair.getPublic()));
        Assert.assertFalse(CryptoUtils.verifyRSA("Other".getBytes(), signature, keyPair.getPublic()));
        Assert.assertFalse(CryptoUtils.verifyRSA(data, "not base64!", keyPair.getPublic()));
    }
}
