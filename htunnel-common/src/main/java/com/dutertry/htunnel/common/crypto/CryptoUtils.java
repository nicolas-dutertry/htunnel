/*
 * htunnel - A simple HTTP tunnel 
 * https://github.com/nicolas-dutertry/htunnel
 * 
 * Written by Nicolas Dutertry.
 * 
 * This file is provided under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
package com.dutertry.htunnel.common.crypto;

import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class CryptoUtils {
    private static final String AES_KEY_ALGO = "AES";
    private static final String AES_ENCRYPT_ALGO = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH_BYTE = 16;
    private static final String RSA_SIGN_ALG = "RSASSA-PSS";
    
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_KEY_ALGO);
        keyGen.init(256);
        return keyGen.generateKey();
    }
    
    public static String encodeAESKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    public static SecretKey decodeAESKey(String encodedKey) {
        return new SecretKeySpec(Base64.getDecoder().decode(encodedKey), AES_KEY_ALGO);
    }
    
    public static byte[] encryptAES(byte[] pText, SecretKey secret) throws GeneralSecurityException  {
        Cipher cipher = Cipher.getInstance(AES_ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] iv = cipher.getIV();
        byte[] encryptedText = cipher.doFinal(pText);
        
        ByteBuffer bb = ByteBuffer.allocate(iv.length + encryptedText.length);
        bb.put(iv);
        bb.put(encryptedText);
        return bb.array();
    }
    
    public static byte[] decryptAES(byte[] cText, SecretKey secret) throws GeneralSecurityException {
        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);
        
        Cipher cipher = Cipher.getInstance(AES_ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
    }
    
    public static PrivateKey readRSAPrivateKey(String keyPath) throws IOException {
        PrivateKeyInfo privateKeyInfo;
        try(FileReader reader = new FileReader(keyPath);
                PEMParser pemParser = new PEMParser(reader)) {
            privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
        }
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return converter.getPrivateKey(privateKeyInfo);
    }
    
    public static PublicKey readRSAPublicKey(String keyPath) throws IOException {
        SubjectPublicKeyInfo subjectPublicKeyInfo;
        try(FileReader reader = new FileReader(keyPath);
                PEMParser pemParser = new PEMParser(reader)) {
            subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
        }
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        return converter.getPublicKey(subjectPublicKeyInfo);
    }
    
    /**
     * Signs data with RSASSA-PSS (SHA-256) and returns the Base64 encoded signature.
     */
    public static String signRSA(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        Signature signature = newSignature();
        signature.initSign(privateKey);
        signature.update(data);
        return Base64.getEncoder().encodeToString(signature.sign());
    }
    
    /**
     * Verifies a Base64 encoded RSASSA-PSS signature.
     */
    public static boolean verifyRSA(byte[] data, String base64Signature, PublicKey publicKey) throws GeneralSecurityException {
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(base64Signature);
        } catch(IllegalArgumentException e) {
            return false;
        }
        Signature signature = newSignature();
        signature.initVerify(publicKey);
        signature.update(data);
        try {
            return signature.verify(signatureBytes);
        } catch(SignatureException e) {
            return false;
        }
    }
    
    private static Signature newSignature() throws GeneralSecurityException {
        Signature signature = Signature.getInstance(RSA_SIGN_ALG);
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        return signature;
    }
}
