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

import com.highmobility.utils.Bytes;
import com.highmobility.utils.Base64;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Created by ttiganik on 13/04/16.
 *
 * Access Certificate is used to recognise and authorise two HM SDK-enabled devices.
 *
 * This class handles both the v0 and v1 certificate types. The getters are the same for both versions.
 * For initialization with specific parameters use the appropriate constructors(that have your required
 * fields and not anything else)
 *
 */
public class AccessCertificate extends Certificate {
    static DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    int version = 0;
    static int v0Length = 93;
    static int v1Length = 98;
    static byte[] v0Issuer = new byte[] { 0x74, 0x6D, 0x63, 0x73 };

    /**
     *
     * @return The certificate's issuer
     */
    public byte[] getIssuer() {
        if (version == 1) {
            byte[] bytes = new byte[4];
            System.arraycopy(this.bytes, 1, bytes, 0, 4);
            return bytes;
        }

        return v0Issuer;
    }

    /**
     * @return The serial number of the device that's providing access.
     */
    public byte[] getProviderSerial() {
        byte[] bytes = new byte[9];

        if (version == 1) {
            System.arraycopy(this.bytes, 5, bytes, 0, 9);
        }
        else {
            System.arraycopy(this.bytes, 73, bytes, 0, 9);
        }

        return bytes;
    }

    /**
     * @return The serial number of the device that's gaining access.
     */
    public byte[] getGainerSerial() {
        byte[] bytes = new byte[9];
        if (version == 1) {
            System.arraycopy(this.bytes, 14, bytes, 0, 9);
        }
        else {
            System.arraycopy(this.bytes, 0, bytes, 0, 9);
        }
        
        return bytes;
    }

    /**
     * @return The public key of the device that's gaining access.
     */
    public byte[] getGainerPublicKey() {
        byte[] bytes = new byte[64];

        if (version == 1) {
            System.arraycopy(this.bytes, 23, bytes, 0, 64);
        }
        else {
            System.arraycopy(this.bytes, 9, bytes, 0, 64);
        }

        return bytes;
    }

    /**
     * @return The certificate validity start date.
     */
    public Calendar getStartDate() {
        return dateFromBytes(getStartDateBytes());
    }

    /**
     * @return The certificate validity start date in byte format.
     */
    public byte[] getStartDateBytes() {
        byte[] bytes = new byte[5];

        if (version == 1) {
            System.arraycopy(this.bytes, 87, bytes, 0, 5);
        }
        else {
            System.arraycopy(this.bytes, 82, bytes, 0, 5);
        }

        return bytes;
    }

    /**
     * @return The certificate validity end date.
     */
    public Calendar getEndDate() {
        byte[] endDateBytes = getEndDateBytes();
        return dateFromBytes(endDateBytes);
    }

    /**
     * @return The certificate validity end date in byte format.
     */
    public byte[] getEndDateBytes() {
        byte[] bytes = new byte[5];
        if (version == 1) {
            System.arraycopy(this.bytes, 92, bytes, 0, 5);
        }
        else {
            System.arraycopy(this.bytes, 87, bytes, 0, 5);
        }

        return bytes;
    }

    /**
     * @return  The permissions given for the certificate, up to 16 bytes and can both contain
     *          arbitrary data as well as permission bytes that correspond to the General API.
     */
    public byte[] getPermissions() {
        int lengthLocation = version == 0 ? 92 : 97;
        int length = bytes[lengthLocation];

        if (length > 0) {
            byte[] bytes = new byte[length];
            System.arraycopy(this.bytes, lengthLocation + 1, bytes, 0, length);
            return bytes;
        } else {
            return new byte[0];
        }
    }

    /**
     * Set the certificate's new permissions. After this the signature is invalidated
     * @param permissions The new permissions, up to 16 bytes.
     */
    public void setPermissions(byte[] permissions) {
        int lengthLocation = version == 0 ? 92 : 97;

        byte length = 0x00;
        byte[] newBytes;

        if (permissions != null && permissions.length > 0) {
            length = (byte) permissions.length;
        }

        newBytes = new byte[lengthLocation + 1 + length];
        System.arraycopy(this.bytes, 0, newBytes, 0, lengthLocation);

        newBytes[lengthLocation] = length;

        if (length > 0) {
            System.arraycopy(newBytes, lengthLocation + 1, permissions, 0, length);
        }

        this.bytes = newBytes;
    }

    /**
     * @return A boolean value indicating if the certificate has expired.
     */
    public boolean isExpired() {
        Calendar endDate = getEndDate();
        return endDate.before(Calendar.getInstance(TimeZone.getTimeZone("UTC")));
    }

    /**
     *
     * @return A boolean indicating if the certificate is not valid yet, but will be in the future
     */
    public boolean isNotValidYet() {
        Calendar startDate = getStartDate();
        return startDate.after(Calendar.getInstance(TimeZone.getTimeZone("UTC")));
    }

    @Override
    public byte[] getCertificateData() {
        int dataLength = version == 1 ? v1Length : v0Length;
        int permissionsLengthPosition = version == 1 ? 97 : 92;

        if (bytes[permissionsLengthPosition] > 0) {
            dataLength += bytes[permissionsLengthPosition];
        }

        byte[] bytes = new byte[dataLength];
        System.arraycopy(this.bytes, 0, bytes, 0, dataLength);
        return bytes;
    }

    @Override
    public byte[] getSignature() {
        int permissionsLengthPosition = version == 1 ? 97 : 92;
        int permissionsSize = bytes[permissionsLengthPosition];

        if (bytes.length == permissionsLengthPosition + 1 + permissionsSize) {
            return null; // no sig
        } else {
            byte[] bytes = new byte[64];
            System.arraycopy(this.bytes, permissionsLengthPosition + 1 + permissionsSize, bytes, 0, 64);
            return bytes;
        }
    }

    /**
     * @param bytes The Certificate Authority's signature for the certificate, 64 bytes
     */
    public void setSignature(byte[] bytes) {
        if (bytes.length == 64) {
            this.bytes = Bytes.concatBytes(getCertificateData(), bytes);
        }
    }

    @Override
    public String toString() {
        String description = "";

        description += "\nissuer: " + Bytes.hexFromBytes(getIssuer());
        description += "\nprovidingSerial: " + Bytes.hexFromBytes(getProviderSerial());
        description += "\ngainingSerial: " + Bytes.hexFromBytes(getGainerSerial());
        description += "\ngainingPublicKey: " + Bytes.hexFromBytes(getGainerPublicKey());
        description += "\nvalid from: : " + dateFormat.format(getStartDate().getTime()) + " to: " + dateFormat.format(getEndDate().getTime());
        description += "\npermissions: " + Bytes.hexFromBytes(getPermissions());
        description += "\nsignature: " + Bytes.hexFromBytes(getSignature()) + "\n";

        return description;
    }

    /**
     * Initialize the access certificate with raw bytes.
     *
     * Signature is not required, but all of the other data is.
     * For manual initialization see the alternative constructors.
     *
     * @param bytes The bytes making up the certificate.
     * @throws IllegalArgumentException When bytes length is not correct.
     */
    public AccessCertificate(byte[] bytes) throws IllegalArgumentException {
        super(bytes);
        testVersion();
        validateBytes();
    }

    /**
     * Initialize the access certificate with raw bytes encoded in Base64.
     *
     * For manual initialization see the alternative constructors.
     *
     * @param base64Bytes The Base64 encoded bytes making up the certificate.
     * @throws IllegalArgumentException When byte count is not correct.
     */
    public AccessCertificate(String base64Bytes) throws IllegalArgumentException {
        this(Base64.decode(base64Bytes));
    }

    /**
     * Initialize the v1 access certificate with all its attributes except Certificate Authority signature.
     *
     * @param issuer            The 4-byte identifier of the issuer of this certificate. Set to null if v0 certificate.
     * @param providingSerial   9-byte serial number of the device providing access to itself.
     * @param gainerSerial      9-byte serial number of the device that's gaining access.
     * @param gainingPublicKey  64-byte public key of the device gaining access.
     * @param startDate         The start time (and date) of the certificate.
     * @param endDate           The expiration time of the certificate.
     * @param permissions       Permissions supplied with the certificate (up to 16 bytes).
     * @throws IllegalArgumentException When parameters are invalid or not in correct size according to the table on top.
     */
    public AccessCertificate(byte[] issuer,
                             byte[] providingSerial,
                             byte[] gainerSerial,
                             byte[] gainingPublicKey,
                             byte[] startDate,
                             byte[] endDate,
                             byte[] permissions) throws IllegalArgumentException {
        super();

        byte[] bytes;

        if (providingSerial.length != 9
            || gainerSerial.length != 9
            || gainingPublicKey.length != 64
            || startDate.length != 5
            || endDate.length != 5) throw new IllegalArgumentException();


        if (issuer == null) {
            bytes = gainerSerial;
            bytes = Bytes.concatBytes(bytes, gainingPublicKey);
            bytes = Bytes.concatBytes(bytes, providingSerial);
        }
        else {
            version = 1;
            bytes = new byte[] { 0x01 };
            bytes = Bytes.concatBytes(bytes, issuer);
            bytes = Bytes.concatBytes(bytes, providingSerial);
            bytes = Bytes.concatBytes(bytes, gainerSerial);
            bytes = Bytes.concatBytes(bytes, gainingPublicKey);
        }

        bytes = Bytes.concatBytes(bytes, startDate);
        bytes = Bytes.concatBytes(bytes, endDate);

        if (permissions != null && permissions.length > 0) {
            bytes = Bytes.concatBytes(bytes, new byte[] {(byte)permissions.length});
            bytes = Bytes.concatBytes(bytes, permissions);
        }
        else {
            bytes = Bytes.concatBytes(bytes, new byte[] {0x00});
        }

        this.bytes = bytes;
        validateBytes();
    }


    /**
     * Initialize the access certificate with all its attributes except Certificate Authority signature.
     *
     * @param issuer            The 4-byte identifier of the issuer of this certificate. Set to null if v0 certificate.
     * @param gainerSerial      9-byte serial number of the device that's gaining access.
     * @param gainingPublicKey  64-byte public key of the device gaining access.
     * @param providingSerial   9-byte serial number of the device providing access to itself.
     * @param startDate         The start time (and date) of the certificate.
     * @param endDate           The expiration date of the certificate.
     * @param permissions       Permissions supplied with the certificate (up to 16 bytes).
     * @throws IllegalArgumentException When parameters are invalid or not in correct size according to the table on top.
     */
    public AccessCertificate(byte[] issuer,
                             byte[] providingSerial,
                             byte[] gainerSerial,
                             byte[] gainingPublicKey,
                             Calendar startDate,
                             Calendar endDate,
                             byte[] permissions) throws IllegalArgumentException {
        this(issuer,
            providingSerial,
            gainerSerial,
            gainingPublicKey,
            bytesFromDate(startDate),
            bytesFromDate(endDate),
            permissions);
    }

    private void validateBytes() throws IllegalArgumentException {
        int expectedLength = version == 1 ? v1Length : v0Length;

        if (bytes == null || bytes.length < expectedLength) {
            throw new IllegalArgumentException();
        }

        if (getEndDate().before(getStartDate())) throw new IllegalArgumentException();
    }

    /**
     * Tests whether bytes are v0 or v1, according to permissions length. If the permissions
     * length(at v0 or v1 location) tests ok for the total length of the bytes, that version is used.
     */
    void testVersion() throws IllegalArgumentException {
        int permissionsLengthPosition, permissionsLength, withoutSignatureLength;

        if (bytes[0] == 1) {
            // try to verify v1
            permissionsLengthPosition = 97;
            if (bytes.length < permissionsLengthPosition + 1) throw new IllegalArgumentException();

            permissionsLength = bytes[permissionsLengthPosition];
            withoutSignatureLength = v1Length + permissionsLength;
            if (bytes.length == withoutSignatureLength || bytes.length == withoutSignatureLength + 64) {
                version = 1;
                return; // is version 1
            }
        }

        // try to verify v0
        permissionsLengthPosition = 92;
        if (bytes.length < permissionsLengthPosition + 1) throw new IllegalArgumentException();

        permissionsLength = bytes[permissionsLengthPosition];
        withoutSignatureLength = v0Length + permissionsLength;
        if (bytes.length != withoutSignatureLength && bytes.length != withoutSignatureLength + 64) {
            throw new IllegalArgumentException(); // bytes are not v0 or v1
        }
    }
}
