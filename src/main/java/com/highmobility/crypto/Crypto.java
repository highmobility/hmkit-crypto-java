/*
 * The MIT License
 *
 * Copyright (c) 2014- High-Mobility GmbH (https://high-mobility.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.highmobility.crypto;

import com.highmobility.btcore.HMBTCore;
import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.PrivateKey;
import com.highmobility.crypto.value.PublicKey;
import com.highmobility.crypto.value.Sha256;
import com.highmobility.crypto.value.Signature;
import com.highmobility.value.Bytes;

import java.util.Random;

public class Crypto {

    private HMBTCore core;

    // HMBTCore is available in either HMKit Android or HMKit OEM.
    public Crypto(HMBTCore core) {
        this.core = core;
    }

    /**
     * Create a keypair.
     *
     * @return The KeyPair.
     */
    public HMKeyPair createKeypair() {
        byte[] privateKey = new byte[32];
        byte[] publicKey = new byte[64];

        core.HMBTCoreCryptoCreateKeys(privateKey, publicKey);
        return new HMKeyPair(new PrivateKey(privateKey), new PublicKey(publicKey));
    }

    /**
     * Create a random serial number.
     *
     * @return the serial number.
     */
    public DeviceSerial createSerialNumber() {
        byte[] serialBytes = new byte[9];
        new Random().nextBytes(serialBytes);
        return new DeviceSerial(serialBytes);
    }

    /**
     * Sign data.
     *
     * @param bytes      The data that will be signed.
     * @param privateKey The private key that will be used for signing.
     * @return The signature.
     */
    public Signature sign(Bytes bytes, PrivateKey privateKey) {
        return sign(bytes.getByteArray(), privateKey.getByteArray());
    }

    /**
     * Sign data.
     *
     * @param bytes      The data that will be signed.
     * @param privateKey The private key that will be used for signing.
     * @return The signature.
     */
    public Signature sign(byte[] bytes, byte[] privateKey) {
        byte[] signature = new byte[64];
        core.HMBTCoreCryptoAddSignature(bytes, bytes.length, privateKey, signature);
        return new Signature(signature);
    }

    /**
     * Verify a signature.
     *
     * @param data      The data that was signed.
     * @param signature The signature.
     * @param publicKey The public key that is used for verifying.
     * @return The verification result.
     */
    public boolean verify(Bytes data, Bytes signature, PublicKey publicKey) {
        return verify(data.getByteArray(), signature.getByteArray(), publicKey.getByteArray());
    }

    /**
     * Verify a signature.
     *
     * @param data      The data that was signed.
     * @param signature The signature.
     * @param publicKey The public key that is used for verifying.
     * @return The verification result.
     */
    public boolean verify(byte[] data, byte[] signature, byte[] publicKey) {
        int result = core.HMBTCoreCryptoValidateSignature(data, data.length, publicKey, signature);
        return result == 0;
    }

    public Signature signJWT(byte[] bytes, PrivateKey privateKey) {
        byte[] signature = new byte[64];
        core.HMBTCoreCryptoJWTAddSignature(bytes, bytes.length,
                privateKey.getByteArray(), signature);
        return new Signature(signature);
    }

    public Signature signJWT(Bytes bytes, PrivateKey privateKey) {
        return signJWT(bytes.getByteArray(), privateKey);
    }

    public Sha256 sha256(byte[] bytes) {
        byte[] sha256 = new byte[32];
        core.HMBTCoreCryptoJWTsha(bytes, bytes.length, sha256);
        return new Sha256(sha256);
    }

    public Sha256 sha256(Bytes bytes) {
        return sha256(bytes.getByteArray());
    }
}
