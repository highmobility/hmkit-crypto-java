package com.highmobility.crypto;


import com.highmobility.utils.Base64;

public class HMKeyPair {
    private static final long serialVersionUID = 6637283024188232326L;
    private byte[] privateKey;
    private byte[] publicKey;

    public HMKeyPair(byte[] privateKey, byte[] publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public String getPublicKeyBase64() {
        return Base64.encode(publicKey);
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public String getPrivateKeyBase64() {
        return Base64.encode(privateKey);
    }
}
