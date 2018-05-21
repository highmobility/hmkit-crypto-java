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

import com.highmobility.utils.Base64;
import com.highmobility.value.AppIdentifier;
import com.highmobility.value.Bytes;
import com.highmobility.value.DeviceSerial;
import com.highmobility.value.Issuer;
import com.highmobility.value.PublicKey;
import com.highmobility.value.Signature;

/**
 * Created by ttiganik on 13/04/16.
 * <p>
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
        // TODO: 17/05/2018 set it as ivar on init and on new permissions set

        if (bytes.getLength() == 89) {
            return bytes;
        }

        byte[] bytes = new byte[89];
        System.arraycopy(this.bytes, 0, bytes, 0, 89);
        return new Bytes(bytes);
    }

    /**
     * @return The Certificate Authority's signature for the certificate, 64 bytes.
     */
    @Override
    public Signature getSignature() {
        // TODO: 17/05/2018 set it as ivar
        if (bytes.getLength() == 153) {
            byte[] bytes = new byte[64];
            System.arraycopy(this.bytes.getBytes(), 89, bytes, 0, 64);
            return new Signature(bytes);
        }

        return null;
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
     * Initialise the device certificate with raw bytes.
     *
     * @param bytes The bytes making up the certificate (89 bytes are expected).
     * @throws IllegalArgumentException When bytes length is incorrect.
     */
    public DeviceCertificate(Bytes bytes) throws IllegalArgumentException {
        // TODO: test:
        super(bytes);
        validateBytes();

        byte[] issuerBytes = new byte[4];
        System.arraycopy(this.bytes.getBytes(), 0, issuerBytes, 0, 4);
        issuer = new Issuer(issuerBytes);

        byte[] appIdentifierBytes = new byte[12];
        System.arraycopy(this.bytes.getBytes(), 4, appIdentifierBytes, 0, 12);
        appIdentifier = new AppIdentifier(appIdentifierBytes);

        byte[] serialBytes = new byte[9];
        System.arraycopy(this.bytes.getBytes(), 16, serialBytes, 0, 9);
        serial = new DeviceSerial(serialBytes);

        byte[] publicKeyBytes = new byte[64];
        System.arraycopy(this.bytes.getBytes(), 25, publicKeyBytes, 0, 64);
        publicKey = new PublicKey(publicKeyBytes);
    }

    /**
     * Initialize the device certificate with raw bytes encoded in Base64.
     * <p>
     * For manual initialization see the alternative constructors.
     *
     * @param base64Bytes The Base64 encoded bytes making up the certificate.
     * @throws IllegalArgumentException When byte count is incorrect.
     * @deprecated use {@link #DeviceCertificate(Bytes)} instead
     */
    @Deprecated
    public DeviceCertificate(String base64Bytes) throws IllegalArgumentException {
        this(new Bytes(Base64.decode(base64Bytes)));
    }

    /**
     * Initialise the device certificate with all its attributes except Certificate Authority
     * signature.
     *
     * @param issuer        The issuer's identifying 4 bytes.
     * @param appIdentifier The specific app's identifying 12 bytes (one issuer might have many apps
     *                      / uses).
     * @param serial        The serial of the device with the certificate that's 9 bytes.
     * @param publicKey     The public key of the device with the certificate that's 64 bytes.
     * @throws IllegalArgumentException When the parameters sizes are wrong.
     */
    public DeviceCertificate(Issuer issuer,
                             AppIdentifier appIdentifier,
                             DeviceSerial serial,
                             PublicKey publicKey) throws IllegalArgumentException {
        super();

        Bytes bytes = new Bytes();
        bytes = bytes.concat(issuer);
        bytes = bytes.concat(appIdentifier);
        bytes = bytes.concat(serial);
        bytes = bytes.concat(publicKey);

        this.issuer = issuer;
        this.appIdentifier = appIdentifier;
        this.serial = serial;
        this.publicKey = publicKey;
        this.certificateData = bytes;

        this.bytes = bytes;
    }

    private void validateBytes() throws IllegalArgumentException {
        if (bytes == null || bytes.getLength() < 89) {
            throw new IllegalArgumentException();
        }
    }
}
