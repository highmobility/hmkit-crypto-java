/*
 * HMKit Crypto - Crypto for Java
 * Copyright (C) 2018 High-Mobility <licensing@high-mobility.com>
 *
 * This file is part of HMKit Crypto.
 *
 * HMKit Crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HMKit Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HMKit Crypto.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.highmobility.crypto;

import com.highmobility.btcore.HMBTCore;
import com.highmobility.utils.Base64;
import com.highmobility.value.Bytes;
import com.highmobility.value.DeviceSerial;
import com.highmobility.value.PrivateKey;
import com.highmobility.value.PublicKey;
import com.highmobility.value.Signature;

import java.util.Random;

public class Crypto {

    private static final HMBTCore core = new HMBTCore();

    /**
     * Create a keypair.
     *
     * @return The KeyPair.
     */
    public static HMKeyPair createKeypair() {
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
    public static DeviceSerial createSerialNumber() {
        byte[] serialBytes = new byte[9];
        new Random().nextBytes(serialBytes);
        return new DeviceSerial(serialBytes);
    }

    /**
     * Add a signature for an access certificate.
     *
     * @param unsignedCert     The access certificate
     * @param privateKeyBase64 The private key that will be used for signing the certificate.
     * @deprecated use {@link #sign(Bytes, PrivateKey)}
     */
    @Deprecated
    public static void sign(AccessCertificate unsignedCert, String privateKeyBase64) {
        sign(unsignedCert, new PrivateKey(Base64.decode(privateKeyBase64)));
    }

    /**
     * Add a signature for an access certificate.
     *
     * @param unsignedCert    The access certificate
     * @param privateKey The private key that will be used for signing the certificate.
     */
    public static void sign(AccessCertificate unsignedCert, PrivateKey privateKey) {
        Signature signature = sign(unsignedCert.getBytes(), privateKey);
        unsignedCert.setSignature(signature);
    }

    /**
     * Sign data.
     *
     * @param bytes   The data that will be signed.
     * @param keyPair The keypair that will be used for signing.
     * @return The signature.
     */
    public static Signature sign(Bytes bytes, HMKeyPair keyPair) {
        return sign(bytes, keyPair.getPrivateKey());
    }

    /**
     * Sign data.
     *
     * @param bytes      The data that will be signed.
     * @param privateKey The private key that will be used for signing.
     * @return The signature.
     */
    public static Signature sign(Bytes bytes, PrivateKey privateKey) {
        byte[] signature = new byte[64];
        core.HMBTCoreCryptoAddSignature(bytes.getBytes(), bytes.getLength(), privateKey.getBytes(), signature);
        return new Signature(signature);
    }

    /**
     * Verify a signature.
     *
     * @param data      The data that was signed.
     * @param signature The signature.
     * @param publicKey The public key that is used for verifying.
     * @return True if verified.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] publicKey) {
        int result = core.HMBTCoreCryptoValidateSignature(data, data.length, publicKey, signature);
        return result == 0;
    }
}
