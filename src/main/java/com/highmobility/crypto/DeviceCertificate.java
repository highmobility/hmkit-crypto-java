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

import com.highmobility.crypto.value.AppIdentifier;
import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.Issuer;
import com.highmobility.crypto.value.PublicKey;
import com.highmobility.crypto.value.Signature;
import com.highmobility.value.Bytes;

/**
 * Device Certificate is used to recognize a valid device.
 * <p>
 * Certificate binary format BytesWithLength[0 to 4]: Issuer (4 bytes) BytesWithLength[4 to 16]: App
 * ID (12 bytes) BytesWithLength[16 to 25]: Device serial (9 bytes) BytesWithLength[25 to 89]:
 * Device Public Key ( 64 bytes) BytesWithLength[89 to 153]: CA Signature ( 64 bytes)
 */
public class DeviceCertificate extends Certificate {
    Issuer issuer;
    AppIdentifier appIdentifier;
    DeviceSerial serial;
    PublicKey publicKey;

    /**
     * @return The certificate issuers identifier.
     */
    public Issuer getIssuer() {
        return issuer;
    }

    /**
     * @return The certificate's app identifier.
     */
    public AppIdentifier getAppIdentifier() {
        return appIdentifier;
    }

    /**
     * @return The serial number of the device.
     */
    public DeviceSerial getSerial() {
        return serial;
    }

    /**
     * @return The public key of the device.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Bytes getCertificateData() {
        return certificateData;
    }

    @Override
    public String toString() {
        String description = "";

        description += "\nissuer: " + getIssuer();
        description += "\nappIdentifer: " + getAppIdentifier();
        description += "\nserial: " + getSerial();
        description += "\npublic key: " + getPublicKey();
        description += "\nsignature: " + getSignature();

        return description;
    }

    /**
     * Initialise the device certificate with raw bytes in hex or Base64.
     *
     * @param bytes The bytes.
     * @throws IllegalArgumentException When bytes length is not correct.
     */
    public DeviceCertificate(String bytes) throws IllegalArgumentException {
        this(new Bytes(bytes));
    }

    /**
     * Initialise the device certificate with raw bytes.
     *
     * @param bytes The bytes making up the certificate (89 bytes are expected).
     * @throws IllegalArgumentException When bytes length is incorrect.
     */
    public DeviceCertificate(Bytes bytes) throws IllegalArgumentException {
        super(bytes);
        validateBytes();

        byte[] issuerBytes = new byte[4];
        System.arraycopy(bytes.getByteArray(), 0, issuerBytes, 0, 4);
        issuer = new Issuer(issuerBytes);

        byte[] appIdentifierBytes = new byte[12];
        System.arraycopy(bytes.getByteArray(), 4, appIdentifierBytes, 0, 12);
        appIdentifier = new AppIdentifier(appIdentifierBytes);

        byte[] serialBytes = new byte[9];
        System.arraycopy(bytes.getByteArray(), 16, serialBytes, 0, 9);
        serial = new DeviceSerial(serialBytes);

        byte[] publicKeyBytes = new byte[64];
        System.arraycopy(bytes.getByteArray(), 25, publicKeyBytes, 0, 64);
        publicKey = new PublicKey(publicKeyBytes);

        if (bytes.getLength() == 153) {
            byte[] sigBytes = new byte[64];
            System.arraycopy(bytes.getByteArray(), 89, sigBytes, 0, 64);
            this.signature = new Signature(sigBytes);

            byte[] value = new byte[89];
            System.arraycopy(bytes.getByteArray(), 0, value, 0, 89);
            certificateData = new Bytes(value);
        } else {
            certificateData = bytes;
        }
    }

    /**
     * Initialise the device certificate with all its attributes except Certificate Authority
     * signature.
     *
     * @param issuer        The issuer's identifying 4 bytes.
     * @param appIdentifier The specific app's identifying 12 bytes (one issuer might have many apps
     *                      / uses).
     * @param serial        The serial of the device with the certificate.
     * @param publicKey     The public key of the device with the certificate.
     */
    public DeviceCertificate(Issuer issuer,
                             AppIdentifier appIdentifier,
                             DeviceSerial serial,
                             PublicKey publicKey) {
        super(4 + 12 + 9 + 64);

        set(0, issuer);
        set(4, appIdentifier);
        set(16, serial);
        set(25, publicKey);

        this.issuer = issuer;
        this.appIdentifier = appIdentifier;
        this.serial = serial;
        this.publicKey = publicKey;
        this.certificateData = new Bytes(this); // no signature bytes
    }

    private void validateBytes() throws IllegalArgumentException {
        int length = getLength();
        if (bytes == null || (length != 89 && length != 153)) {
            throw new IllegalArgumentException();
        }
    }
}
