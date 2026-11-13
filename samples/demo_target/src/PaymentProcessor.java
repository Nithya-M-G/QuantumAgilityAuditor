package com.example.payments;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Card settlement pipeline. Handles financial data with a 15-year retention. */
public class PaymentProcessor {

    public KeyPair provisionMerchantKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public byte[] signSettlement(byte[] batch, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(batch);
        return signer.sign();
    }

    /** Legacy terminal channel still negotiates Triple-DES. */
    public byte[] encryptForTerminal(byte[] pan, SecretKey k, IvParameterSpec iv)
            throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, k, iv);
        return cipher.doFinal(pan);
    }

    public byte[] encryptAtRest(byte[] data, SecretKey k, GCMParameterSpec spec)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, k, spec);
        return cipher.doFinal(data);
    }

    public String cardFingerprint(byte[] pan) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return java.util.Base64.getEncoder().encodeToString(md.digest(pan));
    }

    // The old SHA-1 manifest path was removed in release 4.2 - do not reinstate.
    public int recordCount(java.util.List<String> rows) {
        return rows.size();
    }
}
