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
import com.highmobility.value.Bytes;
import com.highmobility.value.DeviceSerial;
import com.highmobility.value.HMCalendar;
import com.highmobility.value.Issuer;
import com.highmobility.value.Permissions;
import com.highmobility.value.PublicKey;
import com.highmobility.value.Signature;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Created by ttiganik on 13/04/16.
 * <p>
 * Access Certificate is used to recognise and authorise two HM SDK-enabled devices.
 * <p>
 * This class handles both the v0 and v1 certificate types. The getters are the same for both
 * versions. For initialization with specific parameters use the appropriate constructors(that have
 * your required fields and not anything else)
 */
public class AccessCertificate extends Certificate {
    static DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    int version = 0;
    static int v0Length = 93;
    static int v1Length = 98;
    static Issuer v0Issuer = new Issuer("746D6373");

    Issuer issuer;
    DeviceSerial providerSerial;
    DeviceSerial gainerSerial;
    PublicKey gainerPublicKey;
    HMCalendar startDate;
    HMCalendar endDate;
    Permissions permissions;
    Signature signature;

    /**
     * @return The certificate's issuer
     */
    public Issuer getIssuer() {
        // TODO: 17/05/2018
        if (version == 1) {
            byte[] bytes = new byte[4];
            System.arraycopy(this.bytes.getBytes(), 1, bytes, 0, 4);
            return new Issuer(bytes);
        }

        return v0Issuer;
    }

    /**
     * @return The serial number of the device that's providing access.
     */
    public DeviceSerial getProviderSerial() {
        // TODO: 17/05/2018
        byte[] bytes = new byte[9];

        if (version == 1) {
            System.arraycopy(this.bytes.getBytes(), 5, bytes, 0, 9);
        } else {
            System.arraycopy(this.bytes.getBytes(), 73, bytes, 0, 9);
        }

        return new DeviceSerial(bytes);
    }

    /**
     * @return The serial number of the device that's gaining access.
     */
    public DeviceSerial getGainerSerial() {
        // TODO: 17/05/2018
        byte[] bytes = new byte[9];
        if (version == 1) {
            System.arraycopy(this.bytes.getBytes(), 14, bytes, 0, 9);
        } else {
            System.arraycopy(this.bytes.getBytes(), 0, bytes, 0, 9);
        }

        return new DeviceSerial(bytes);
    }

    /**
     * @return The public key of the device that's gaining access.
     */
    public PublicKey getGainerPublicKey() {
        // TODO: 17/05/2018
        byte[] bytes = new byte[64];

        if (version == 1) {
            System.arraycopy(this.bytes.getBytes(), 23, bytes, 0, 64);
        } else {
            System.arraycopy(this.bytes.getBytes(), 9, bytes, 0, 64);
        }

        return new PublicKey(bytes);
    }

    /**
     * @return The certificate validity start date.
     */
    public HMCalendar getStartDate() {
        // TODO: 21/05/2018 ivar 
        return new HMCalendar(getStartDateBytes().getBytes());
    }

    /**
     * @return The certificate validity start date in byte format.
     * @deprecated use {@link #getStartDate()} instead.
     */
    @Deprecated
    public Bytes getStartDateBytes() {
        byte[] bytes = new byte[5];

        if (version == 1) {
            System.arraycopy(this.bytes.getBytes(), 87, bytes, 0, 5);
        } else {
            System.arraycopy(this.bytes.getBytes(), 82, bytes, 0, 5);
        }

        return new Bytes(bytes);
    }

    /**
     * @return The certificate validity end date.
     */
    public HMCalendar getEndDate() {
        // TODO: 21/05/2018 ivar
        return new HMCalendar(getEndDateBytes().getBytes());
    }

    /**
     * @return The certificate validity end date in byte format.
     * @deprecated use {@link #getEndDate()} instead.
     */
    @Deprecated
    public Bytes getEndDateBytes() {
        byte[] bytes = new byte[5];
        if (version == 1) {
            System.arraycopy(this.bytes.getBytes(), 92, bytes, 0, 5);
        } else {
            System.arraycopy(this.bytes.getBytes(), 87, bytes, 0, 5);
        }

        return new Bytes(bytes);
    }

    /**
     * @return The permissions given for the certificate, up to 16 bytes and can both contain
     * arbitrary data as well as permission bytes that correspond to the General API.
     */
    public Permissions getPermissions() {
        // TODO: 17/05/2018
        int lengthLocation = version == 0 ? 92 : 97;
        int length = bytes.getBytes()[lengthLocation];

        if (length > 0) {
            byte[] bytes = new byte[length];
            System.arraycopy(this.bytes.getBytes(), lengthLocation + 1, bytes, 0, length);
            return new Permissions(bytes);
        } else {
            return new Permissions();
        }
    }

    /**
     * Set the new permissions. After this the signature is invalidated.
     *
     * @param permissions The new permissions, up to 16 bytes.
     */
    public void setPermissions(Permissions permissions) {
        int lengthLocation = version == 0 ? 92 : 97;

        byte length = (byte) permissions.getLength();
        byte[] newBytes;

        newBytes = new byte[lengthLocation + 1 + length];
        System.arraycopy(this.bytes.getBytes(), 0, newBytes, 0, lengthLocation);

        newBytes[lengthLocation] = length;

        if (length > 0) {
            System.arraycopy(newBytes, lengthLocation + 1, permissions.getBytes(), 0, length);
        }

        this.bytes = new Bytes(newBytes);
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
    public Bytes getCertificateData() {
        // TODO: 17/05/2018 set it as ivar on init and on new permissions set
        int dataLength = version == 1 ? v1Length : v0Length;
        int permissionsLengthPosition = version == 1 ? 97 : 92;

        if (bytes.getBytes()[permissionsLengthPosition] > 0) {
            dataLength += bytes.getBytes()[permissionsLengthPosition];
        }

        byte[] bytes = new byte[dataLength];
        System.arraycopy(this.bytes.getBytes(), 0, bytes, 0, dataLength);
        return new Bytes(bytes);
    }

    @Override
    public Signature getSignature() {
        // TODO: 17/05/2018 use ivar (set on init and addSignature, null with new setPermissions)
        int permissionsLengthPosition = version == 1 ? 97 : 92;
        int permissionsSize = bytes.getBytes()[permissionsLengthPosition];

        if (bytes.getLength() == permissionsLengthPosition + 1 + permissionsSize) {
            return null; // no sig
        } else {
            byte[] bytes = new byte[64];
            System.arraycopy(this.bytes.getBytes(), permissionsLengthPosition + 1 + permissionsSize, bytes,
                    0, 64);
            return new Signature(bytes);
        }
    }

    /**
     * Set the signature.
     *
     * @param signature The Certificate Authority's signature for the certificate
     */
    public void setSignature(Signature signature) {
        // all of the ivars stay the same, only the last signature bytes of the cert change.
        bytes = Bytes.concat(getCertificateData(), signature);
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
    }

    /**
     * Initialize the access certificate with raw bytes encoded in Base64.
     * <p>
     * For manual initialization see the alternative constructors.
     *
     * @param base64Bytes The Base64 encoded bytes making up the certificate.
     * @throws IllegalArgumentException When byte count is not correct.
     * @deprecated Use {@link #AccessCertificate(Bytes)} instead.
     */
    @Deprecated
    public AccessCertificate(String base64Bytes) throws IllegalArgumentException {
        this(new Bytes(Base64.decode(base64Bytes)));
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
                             Permissions permissions) throws IllegalArgumentException {
        super();

        Bytes bytesBuilder;

        if (issuer == null) {
            bytesBuilder = gainerSerial;
            bytesBuilder = Bytes.concat(bytesBuilder, gainingPublicKey);
            bytesBuilder = Bytes.concat(bytesBuilder, providingSerial);
        } else {
            version = 1;
            bytesBuilder = new Bytes("01");
            bytesBuilder = Bytes.concat(bytesBuilder, issuer);
            bytesBuilder = Bytes.concat(bytesBuilder, providingSerial);
            bytesBuilder = Bytes.concat(bytesBuilder, gainerSerial);
            bytesBuilder = Bytes.concat(bytesBuilder, gainingPublicKey);
        }

        bytesBuilder = Bytes.concat(bytesBuilder, startDate);
        bytesBuilder = Bytes.concat(bytesBuilder, endDate);

        if (permissions != null && permissions.getLength() > 0) {
            bytesBuilder = Bytes.concat(bytesBuilder, new Bytes(new byte[]{(byte) permissions
                    .getLength()}));
            bytesBuilder = Bytes.concat(bytesBuilder, permissions);
        } else {
            bytesBuilder = Bytes.concat(bytesBuilder, new Bytes("00"));
        }

        this.bytes = bytesBuilder;
        validateBytes();
    }

    /**
     * Initialize the access certificate with all its attributes except Certificate Authority
     * signature.
     *
     * @param issuer           The 4-byte identifier of the issuer of this certificate. Set to null
     *                         if v0 certificate.
     * @param gainerSerial     9-byte serial number of the device that's gaining access.
     * @param gainingPublicKey 64-byte public key of the device gaining access.
     * @param providingSerial  9-byte serial number of the device providing access to itself.
     * @param startDate        The start time (and date) of the certificate.
     * @param endDate          The expiration date of the certificate.
     * @param permissions      Permissions supplied with the certificate (up to 16 bytes).
     * @throws IllegalArgumentException When parameters are invalid or not in correct size according
     *                                  to the table on top.
     * @deprecated use {@link #AccessCertificate(Issuer, DeviceSerial, DeviceSerial, PublicKey,
     * HMCalendar, HMCalendar, Permissions)} instead
     */
    @Deprecated
    public AccessCertificate(Issuer issuer,
                             DeviceSerial providingSerial,
                             DeviceSerial gainerSerial,
                             PublicKey gainingPublicKey,
                             Calendar startDate,
                             Calendar endDate,
                             Permissions permissions) throws IllegalArgumentException {
        this(issuer,
                providingSerial,
                gainerSerial,
                gainingPublicKey,
                new HMCalendar(startDate),
                new HMCalendar(endDate),
                permissions);
    }

    private void validateBytes() throws IllegalArgumentException {
        int expectedLength = version == 1 ? v1Length : v0Length;

        if (bytes.getLength() < expectedLength) {
            throw new IllegalArgumentException();
        }

        if (getEndDate().getCalendar().before(getStartDate().getCalendar())) throw new IllegalArgumentException();
    }

    /**
     * Tests whether bytes are v0 or v1, according to permissions length. If the permissions
     * length(at v0 or v1 location) tests ok for the total length of the bytes, that version is
     * used.
     */
    void testVersion() throws IllegalArgumentException {
        int permissionsLengthPosition, permissionsLength, withoutSignatureLength;

        if (bytes.getBytes()[0] == 1) {
            // try to verify v1
            permissionsLengthPosition = 97;
            if (bytes.getLength() < permissionsLengthPosition + 1)
                throw new IllegalArgumentException();

            permissionsLength = bytes.getBytes()[permissionsLengthPosition];
            withoutSignatureLength = v1Length + permissionsLength;
            if (bytes.getLength() == withoutSignatureLength || bytes.getLength() ==
                    withoutSignatureLength
                            + 64) {
                version = 1;
                return; // is version 1
            }
        }

        // try to verify v0
        permissionsLengthPosition = 92;
        if (bytes.getLength() < permissionsLengthPosition + 1) throw new IllegalArgumentException();

        permissionsLength = bytes.getBytes()[permissionsLengthPosition];
        withoutSignatureLength = v0Length + permissionsLength;
        if (bytes.getLength() != withoutSignatureLength && bytes.getLength() !=
                withoutSignatureLength + 64) {
            throw new IllegalArgumentException(); // bytes are not v0 or v1
        }
    }
}
