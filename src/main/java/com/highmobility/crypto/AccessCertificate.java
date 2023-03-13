/*
 * The MIT License
 *
 * Copyright (c) 2023- High-Mobility GmbH (https://high-mobility.com)
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

import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.HMCalendar;
import com.highmobility.crypto.value.Issuer;
import com.highmobility.crypto.value.Permissions;
import com.highmobility.crypto.value.PublicKey;
import com.highmobility.crypto.value.Signature;
import com.highmobility.value.Bytes;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Access Certificate is used to recognise and authorise two HM SDK-enabled devices.
 * <p>
 * This class handles both the v0 and v1 certificate types. The getters are the same for both
 * versions. For initialization with specific parameters use the appropriate constructors(that have
 * your required fields and not anything else)
 */
public class AccessCertificate extends Certificate {
    private static final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
    private static final Issuer v0Issuer = new Issuer("746D6373");
    private static final int v0Length = 93;
    private static final int v1Length = 98;

    int version = 0;
    Issuer issuer;
    DeviceSerial providerSerial;
    DeviceSerial gainerSerial;
    PublicKey gainerPublicKey;
    HMCalendar startDate;
    HMCalendar endDate;
    Permissions permissions;

    /**
     * @return The certificate's issuer
     */
    public Issuer getIssuer() {
        return issuer;
    }

    /**
     * @return The serial number of the device that's providing access.
     */
    public DeviceSerial getProviderSerial() {
        return providerSerial;
    }

    /**
     * @return The serial number of the device that's gaining access.
     */
    public DeviceSerial getGainerSerial() {
        return gainerSerial;
    }

    /**
     * @return The public key of the device that's gaining access.
     */
    public PublicKey getGainerPublicKey() {
        return gainerPublicKey;
    }

    /**
     * @return The certificate validity start date.
     */
    public HMCalendar getStartDate() {
        return startDate;
    }

    /**
     * @return The certificate validity end date.
     */
    public HMCalendar getEndDate() {
        return endDate;
    }

    /**
     * @return The permissions given for the certificate, up to 16 bytes and can both contain
     * arbitrary data as well as permission bytes that correspond to the General API.
     */
    public Permissions getPermissions() {
        return permissions;
    }

    /**
     * Set the new permissions. After this the signature is invalidated.
     *
     * @param permissions The new permissions, up to 16 bytes.
     */
    public void setPermissions(Permissions permissions) {
        int lengthLocation = version == 0 ? 92 : 97;

        byte length = (byte) permissions.getLength();
        byte[] newBytes = new byte[lengthLocation + 1 + length];

        System.arraycopy(this.bytes, 0, newBytes, 0, lengthLocation);
        newBytes[lengthLocation] = length;

        if (length > 0) {
            System.arraycopy(permissions.getByteArray(), 0, newBytes, lengthLocation + 1, length);
        }

        this.bytes = newBytes;
        this.permissions = permissions;
        updateCertificateData();
        setSignature(null);
    }

    /**
     * @return A boolean value indicating if the certificate has expired.
     */
    public boolean isExpired() {
        Calendar endDate = getEndDate().getCalendar();
        return endDate.before(Calendar.getInstance(TimeZone.getTimeZone("UTC")));
    }

    /**
     * @return A boolean indicating if the certificate is not valid yet, but will be in the future.
     */
    public boolean isNotValidYet() {
        Calendar startDate = getStartDate().getCalendar();
        return startDate.after(Calendar.getInstance(TimeZone.getTimeZone("UTC")));
    }

    @Override
    public String toString() {
        String description = "";

        description += "\nissuer: " + getIssuer();
        description += "\nprovidingSerial: " + getProviderSerial();
        description += "\ngainingSerial: " + getGainerSerial();
        description += "\ngainingPublicKey: " + getGainerPublicKey();
        description += "\nvalid from: : " + dateFormat.format(getStartDate().getCalendar()
                .getTime()) + " to: "
                + dateFormat.format(getEndDate().getCalendar().getTime());
        description += "\npermissions: " + getPermissions();
        description += "\nsignature: " + getSignature() + "\n";

        return description;
    }

    /**
     * Initialise the Access Certificate with raw bytes in hex or Base64.
     *
     * @param bytes The bytes.
     * @throws IllegalArgumentException When bytes length is not correct.
     */
    public AccessCertificate(String bytes) throws IllegalArgumentException {
        this(new Bytes(bytes));
    }

    /**
     * Initialize the access certificate with Bytes.
     * <p>
     * Signature is not required, but all of the other data is. For manual initialization see the
     * alternative constructors.
     *
     * @param bytes The bytes making up the certificate.
     * @throws IllegalArgumentException When bytes length is not correct.
     */
    public AccessCertificate(Bytes bytes) throws IllegalArgumentException {
        super(bytes);
        testVersion();
        validateBytes();

        if (version == 1) {
            byte[] value = new byte[4];
            System.arraycopy(bytes.getByteArray(), 1, value, 0, 4);
            issuer = new Issuer(value);
        } else {
            issuer = v0Issuer;
        }

        // provider serial
        byte[] providerSerialBytes = new byte[9];
        if (version == 1) {
            System.arraycopy(bytes.getByteArray(), 5, providerSerialBytes, 0, 9);
        } else {
            System.arraycopy(bytes.getByteArray(), 73, providerSerialBytes, 0, 9);
        }
        providerSerial = new DeviceSerial(providerSerialBytes);

        // gainer serial
        byte[] gainerSerialBytes = new byte[9];
        if (version == 1) {
            System.arraycopy(bytes.getByteArray(), 14, gainerSerialBytes, 0, 9);
        } else {
            System.arraycopy(bytes.getByteArray(), 0, gainerSerialBytes, 0, 9);
        }
        gainerSerial = new DeviceSerial(gainerSerialBytes);

        // gainer public key
        byte[] gainerPublicKeyBytes = new byte[64];
        if (version == 1) {
            System.arraycopy(bytes.getByteArray(), 23, gainerPublicKeyBytes, 0, 64);
        } else {
            System.arraycopy(bytes.getByteArray(), 9, gainerPublicKeyBytes, 0, 64);
        }
        gainerPublicKey = new PublicKey(gainerPublicKeyBytes);

        // start date
        byte[] startDateBytes = new byte[5];
        if (version == 1) {
            System.arraycopy(this.bytes, 87, startDateBytes, 0, 5);
        } else {
            System.arraycopy(this.bytes, 82, startDateBytes, 0, 5);
        }
        startDate = new HMCalendar(startDateBytes);

        // end date
        byte[] endDateBytes = new byte[5];
        if (version == 1) {
            System.arraycopy(bytes.getByteArray(), 92, endDateBytes, 0, 5);
        } else {
            System.arraycopy(bytes.getByteArray(), 87, endDateBytes, 0, 5);
        }
        endDate = new HMCalendar(endDateBytes);

        // permissions
        int permissionsLengthLocation = version == 0 ? 92 : 97;

        int permissionsLength = bytes.getByteArray()[permissionsLengthLocation];

        if (permissionsLength > 0) {
            byte[] permissionsBytes = new byte[permissionsLength];
            System.arraycopy(bytes.getByteArray(), permissionsLengthLocation + 1, permissionsBytes,
                    0, permissionsLength);
            permissions = new Permissions(permissionsBytes);
        } else {
            permissions = new Permissions();
        }

        if (bytes.getLength() > permissionsLengthLocation + 1 + permissionsLength) {
            byte[] signatureBytes = new byte[64];
            System.arraycopy(this.bytes, permissionsLengthLocation + 1 +
                            permissionsLength, signatureBytes,
                    0, 64);
            signature = new Signature(signatureBytes);
        }

        if (getEndDate().getCalendar().before(getStartDate().getCalendar()))
            throw new IllegalArgumentException("End date is before start date");

        updateCertificateData();
    }

    /**
     * Initialize the v1 access certificate with all its attributes except Certificate Authority
     * signature.
     *
     * @param issuer           The 4-byte identifier of the issuer of this certificate. Set to null
     *                         if v0 certificate.
     * @param providingSerial  9-byte serial number of the device providing access to itself.
     * @param gainerSerial     9-byte serial number of the device that's gaining access.
     * @param gainingPublicKey 64-byte public key of the device gaining access.
     * @param startDate        The start time (and date) of the certificate.
     * @param endDate          The expiration time of the certificate.
     * @param permissions      Permissions supplied with the certificate (up to 16 bytes).
     * @throws IllegalArgumentException When parameters are invalid or not in correct size according
     *                                  to the table on top.
     */
    public AccessCertificate(Issuer issuer,
                             DeviceSerial providingSerial,
                             DeviceSerial gainerSerial,
                             PublicKey gainingPublicKey,
                             HMCalendar startDate,
                             HMCalendar endDate,
                             Permissions permissions) {
        super();

        Bytes bytesBuilder;

        if (issuer == null) {
            bytesBuilder = gainerSerial;
            bytesBuilder = concat(bytesBuilder, gainingPublicKey);
            bytesBuilder = concat(bytesBuilder, providingSerial);
        } else {
            version = 1;
            bytesBuilder = new Bytes("01");
            bytesBuilder = concat(bytesBuilder, issuer);
            bytesBuilder = concat(bytesBuilder, providingSerial);
            bytesBuilder = concat(bytesBuilder, gainerSerial);
            bytesBuilder = concat(bytesBuilder, gainingPublicKey);
        }

        bytesBuilder = concat(bytesBuilder, startDate);
        bytesBuilder = concat(bytesBuilder, endDate);

        if (permissions != null && permissions.getLength() > 0) {
            bytesBuilder = concat(bytesBuilder, new Bytes(new byte[]{(byte) permissions
                    .getLength()}));
            bytesBuilder = concat(bytesBuilder, permissions);
        } else {
            bytesBuilder = concat(bytesBuilder, new Bytes("00"));
        }

        this.bytes = bytesBuilder.getByteArray();
        validateBytes();

        this.issuer = issuer;
        this.providerSerial = providingSerial;
        this.gainerSerial = gainerSerial;
        this.gainerPublicKey = gainingPublicKey;
        this.startDate = startDate;
        this.endDate = endDate;
        this.permissions = permissions;
        updateCertificateData();
    }

    private void validateBytes() throws IllegalArgumentException {
        int expectedLength = version == 1 ? v1Length : v0Length;

        if (bytes.length < expectedLength) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Tests whether bytes are v0 or v1, according to permissions length. If the permissions
     * length(at v0 or v1 location) tests ok for the total length of the bytes, that version is
     * used.
     */
    void testVersion() throws IllegalArgumentException {
        int permissionsLengthPosition, permissionsLength, withoutSignatureLength;

        if (bytes[0] == 1) {
            // try to verify v1
            permissionsLengthPosition = 97;
            if (bytes.length < permissionsLengthPosition + 1)
                throw new IllegalArgumentException();

            permissionsLength = bytes[permissionsLengthPosition];
            withoutSignatureLength = v1Length + permissionsLength;
            if (bytes.length == withoutSignatureLength || bytes.length ==
                    withoutSignatureLength
                            + 64) {
                version = 1;
                return; // is version 1
            }
        }

        // try to verify v0
        permissionsLengthPosition = 92;
        if (bytes.length < permissionsLengthPosition + 1)
            throw new IllegalArgumentException();

        permissionsLength = bytes[permissionsLengthPosition];
        withoutSignatureLength = v0Length + permissionsLength;
        if (bytes.length != withoutSignatureLength && bytes.length !=
                withoutSignatureLength + 64) {
            throw new IllegalArgumentException(); // bytes are not v0 or v1
        }
    }

    private void updateCertificateData() {
        int dataLength = version == 1 ? v1Length : v0Length;
        int permissionsLengthPosition = version == 1 ? 97 : 92;

        if (bytes[permissionsLengthPosition] > 0) {
            dataLength += bytes[permissionsLengthPosition];
        }

        byte[] bytes = new byte[dataLength];
        System.arraycopy(this.bytes, 0, bytes, 0, dataLength);
        certificateData = new Bytes(bytes);
    }
}
