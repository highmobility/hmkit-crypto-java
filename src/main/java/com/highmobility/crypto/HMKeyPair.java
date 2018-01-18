package com.highmobility.crypto;


import com.highmobility.utils.Base64;

/**
 * ECC private/public keypair that uses elliptic curve P-256.
 */
public class HMKeyPair {
    private static final long serialVersionUID = 6637283024188232326L;
    private byte[] privateKey;
    private byte[] publicKey;

    /**
     * Create a ECC Keypair object with private and public key.
     *
     * @param privateKey The 32 bytes of the private key.
     * @param publicKey The 64 bytes of the public key.
     * @throws IllegalArgumentException When the keys are invalid.
     */
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     *
     * @return The public key.
     */
    public byte[] getPublicKey() {
        return publicKey;
    }

    /**
     *
     * @return The public key in Base64.
     */
    public String getPublicKeyBase64() {
        return Base64.encode(publicKey);
    }

    /**
     *
     * @return The private key.
     */
    public byte[] getPrivateKey() {
        return privateKey;
    }

    /**
     *
     * @return The private key in Base64.
     */
    public String getPrivateKeyBase64() {
        return Base64.encode(privateKey);
    }
}
