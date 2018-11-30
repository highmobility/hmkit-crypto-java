package com.highmobility.crypto.value;

import com.highmobility.utils.ByteUtils;
import com.highmobility.utils.Range;
import com.highmobility.value.BitLocation;
import com.highmobility.value.Bytes;
import com.highmobility.value.BytesWithLength;

import java.util.Arrays;

/**
 * Representation of the Access Certificates permissions field.
 */
public class Permissions extends BytesWithLength {
    private static final Range range = new Range(0, 16);

    private Type type;

    public Type getType() {
        return type;
    }

    /**
     * @param value The raw bytes.
     */
    public Permissions(Bytes value) {
        super(value);
    }

    /**
     * @param value The bytes in hex or Base64.
     */
    public Permissions(String value) {
        super(value);
    }

    /**
     * @param bytes The raw bytes.
     */
    public Permissions(byte[] bytes) {
        super(bytes);
    }

    /**
     * No permissions.
     */
    public Permissions() {
        super();
    }

    /**
     * Initialise the permissions for the given type. Use {@link #allow(Permission)} to add the
     * permissions. By default none of the permissions are allowed.
     *
     * @param type The permissions type.
     */
    public Permissions(Type type) {
        this(getInitialiseBytes(type));
        this.type = type;
    }

    static byte[] getInitialiseBytes(Type type) {
        byte[] bytes = null;

        switch (type) {
            case AUTO_API:
                bytes = new byte[11];
                bytes[0] = 0x10;
                break;
            case CAR_RENTAL:
                bytes = new byte[16];
                bytes[0] = 0x20;
                break;
        }

        return bytes;
    }

    /**
     * @param location The bit location.
     * @return Whether permission at the given location is allowed.
     */
    public boolean isAllowed(BitLocation location) {
        if (location.getByteLocation() > range.getEnd() - 1)
            throw new IllegalArgumentException("Max permission location is " + range.getEnd());

        return ByteUtils.getBit(bytes[location.getByteLocation()], location.getBitLocation());
    }

    /**
     * @param permission The permission.
     * @return Whether given permission is present.
     */
    public boolean hasPermission(Permission permission) {
        return isAllowed(permission.getBitLocation()) == permission.isAllowed();
    }

    /**
     * Set the permission value.
     *
     * @param permissionLocation The permission bit location.
     * @param allow              Whether the permission is allowed. Default is not allowed.
     */
    public void allow(BitLocation permissionLocation, boolean allow) {
        if (permissionLocation.getByteLocation() > range.getEnd() - 1)
            throw new IllegalArgumentException("Max permission length is " + range.getEnd());

        if (permissionLocation.getByteLocation() > bytes.length - 1) {
            bytes = Arrays.copyOf(bytes, permissionLocation.getByteLocation() + 1);
        }

        byte permissionByte = bytes[permissionLocation.getByteLocation()];

        if (allow) permissionByte |= 1 << permissionLocation.getBitLocation();
        else permissionByte &= ~(1 << permissionLocation.getBitLocation());

        bytes[permissionLocation.getByteLocation()] = permissionByte;
    }

    /**
     * Set a permission.
     *
     * @param permission The permission.
     */
    public void allow(Permission permission) {
        allow(permission.getBitLocation(), permission.allowed);
    }

    /**
     * General permissions.
     */

    /**
     * Set the permission to allow the reading of the list of stored certificates (trusted
     * devices).
     *
     * @param allow Whether to allow the permission.
     */
    public void allowCertificatesRead(boolean allow) {
        allow(Permission.certificatesReadPermission(allow));
    }

    /**
     * Set the permission to allow the revoke of access certificates.
     *
     * @param allow Whether to allow the permission.
     */
    public void allowCertificatesWrite(boolean allow) {
        allow(Permission.certificatesWritePermission(allow));
    }

    @Override protected Range getExpectedRange() {
        return range;
    }

    public enum Type {AUTO_API, CAR_RENTAL}
}
