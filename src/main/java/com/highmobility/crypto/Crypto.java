package com.highmobility.crypto;

import com.highmobility.btcore.HMBTCore;
import com.highmobility.utils.Base64;

import java.util.Random;

/**
 * Created by ttiganik on 26/05/16.
 */
public class Crypto {

    private static final HMBTCore core = new HMBTCore();

    public static KeyPair createKeypair() {
        byte[] privateKey = new byte[32];
        byte[] publicKey = new byte[64];

        core.HMBTCoreCryptoCreateKeys(privateKey, publicKey);
        return new KeyPair(privateKey, publicKey);
    }

    public static byte[] createSerialNumber() {
        byte[] serialBytes = new byte[9];
        new Random().nextBytes(serialBytes);
        return serialBytes;
    }

    public static void sign(AccessCertificate unsignedCert, String privateKeyBase64) {
        sign(unsignedCert, Base64.decode(privateKeyBase64));
    }

    public static void sign(AccessCertificate unsignedCert, byte[] privateKeyBytes) {
        byte[] signature = sign(unsignedCert.getBytes(), privateKeyBytes);
        unsignedCert.setSignature(signature);
    }

    public static byte[] sign(byte[] bytes, HMKeyPair keyPair) {
        return sign(bytes, keyPair.getPrivateKey());
    }

    public static byte[] sign(byte[] bytes, byte[] privateKey) {
        byte[] signature = new byte[64];
        core.HMBTCoreCryptoAddSignature(bytes, bytes.length, privateKey, signature);
        return signature;
    }

    public static boolean verify(byte[] data, byte[] signature, byte[] publicKey) {
        int result = core.HMBTCoreCryptoValidateSignature(data, data.length, publicKey, signature);
        return result == 0;
    }
}
