package com.highmobility.crypto.value;

import com.highmobility.value.BitLocation;

public class Permission {
    boolean allowed;
    BitLocation location;

    /**
     * @return Whether the permission is allowed.
     */
    public boolean isAllowed() {
        return allowed;
    }

    /**
     * @return The byte and bit location.
     */
    public BitLocation getBitLocation() {
        return location;
    }

    /**
     * General permissions.
     */

    /**
     * @param allowed Whether to allow the permission.
     * @return The certificates read permission.
     */
    public static Permission certificatesReadPermission(boolean allowed) {
        return new Permission(new BitLocation(1, 0), allowed);
    }

    /**
     * @param allowed Whether to allow the permission.
     * @return The certificates write permission.
     */
    public static Permission certificatesWritePermission(boolean allowed) {
        return new Permission(new BitLocation(1, 1), allowed);
    }

    public Permission(BitLocation location, boolean allowed) {
        this.allowed = allowed;
        this.location = location;
    }
}