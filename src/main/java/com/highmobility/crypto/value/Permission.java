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

    // MARK: General permissions

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