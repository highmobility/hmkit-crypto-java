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
package com.highmobility.test;

import com.highmobility.autoapi.Identifier;
import com.highmobility.autoapi.certificate.PermissionLocation;
import com.highmobility.crypto.AccessCertificate;
import com.highmobility.crypto.value.Permission;
import com.highmobility.crypto.value.Permissions;
import com.highmobility.crypto.value.custom.CarRentalBookingIdentifier;
import com.highmobility.crypto.value.custom.CarRentalPermissions;
import com.highmobility.value.BitLocation;
import com.highmobility.value.Bytes;

import org.junit.Test;

import static junit.framework.TestCase.assertTrue;

public class PermissionsTest {

    @Test(expected = IllegalArgumentException.class)
    public void outOfRangeThrows() {
        Permission permission = new Permission(new BitLocation(16, 1), true);
        Permissions permissions = new Permissions();
        permissions.allow(permission);
    }

    @Test public void growsIfNeeded() {
        // test that if permissions bytes are made bigger if needed
        Permissions permissions = new Permissions();
        permissions.allow(new Permission(new BitLocation(2, 2), true));
        assertTrue(permissions.getLength() == 3);
    }

    @Test public void testPermissionChanges() {
        Permissions permissions = new Permissions();
        BitLocation location = new BitLocation(2, 2);
        permissions.allow(new Permission(new BitLocation(2, 2), true));
        assertTrue(permissions.isAllowed(location));
        permissions.allow(new Permission(new BitLocation(2, 2), false));
        assertTrue(permissions.isAllowed(location) == false);
    }

    @Test public void testAddingDefaultPermission() {
        Permissions permissions = new Permissions();
        permissions.allow(Permission.certificatesReadPermission(true));
        assertTrue(permissions.hasPermission(Permission.certificatesReadPermission(true)));
    }

    @Test public void testIsAllowed() {
        Permissions permissions = new Permissions(Permissions.Type.AUTO_API);
        BitLocation location = new BitLocation(1, 1);
        permissions.allow(new Permission(location, true));
        assertTrue(permissions.isAllowed(location));
        assertTrue(permissions.equals("1002000000000000000000"));
    }

    @Test public void testCertRead() {
        Permissions permissions = new Permissions();
        permissions.allowCertificatesRead(true);
        assertTrue(permissions.isAllowed(new BitLocation(1, 0)));
    }

    @Test public void testCertWrite() {
        Permissions permissions = new Permissions();
        permissions.allowCertificatesWrite(true);
        assertTrue(permissions.isAllowed(new BitLocation(1, 1)));
    }

    @Test public void testCertificateBytes() {
        Permissions permissions = new Permissions();

        // 0x00, 0x03
        permissions.allow(new Permission(new BitLocation(1, 0), true));
        permissions.allow(new Permission(new BitLocation(1, 1), true));

        AccessCertificate cert = new AccessCertificate(new Bytes
                ("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000607010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B"));
        cert.setPermissions(permissions);
        Permissions certPermissions = cert.getPermissions();
        assertTrue(certPermissions.equals("0003"));
    }

    @Test public void testAutoApiInit() {
        // Permissions class is in crypto package.
        Permissions permissions = new Permissions(Permissions.Type.AUTO_API);
        // general permissions are added as methods.
        permissions.allowCertificatesRead(true);
        permissions.allowCertificatesWrite(true);

        // Auto API package is used to get the bit locations for AutoAPI permissions.
        BitLocation carSdkReset = PermissionLocation.allowCarSdkResetLocation();
        BitLocation doorLocksRead = PermissionLocation.locationFor(Identifier.DOORS,
                PermissionLocation.Type.READ);
        BitLocation doorLocksWrite = PermissionLocation.locationFor(Identifier.DOORS,
                PermissionLocation.Type.WRITE);

        BitLocation tachoGraphRead = PermissionLocation.locationFor(Identifier.TACHOGRAPH,
                PermissionLocation.Type.READ);

        // Custom permissions are added as BitLocations and booleans
        permissions.allow(carSdkReset, true);
        permissions.allow(doorLocksRead, true);
        permissions.allow(doorLocksWrite, true);
        permissions.allow(tachoGraphRead, true);

        permissions.allow(PermissionLocation.locationFor(Identifier.CRUISE_CONTROL,
                PermissionLocation.Type.READ), true);
        permissions.allow(PermissionLocation.locationFor(Identifier.CRUISE_CONTROL,
                PermissionLocation.Type.WRITE), true);

        permissions.allow(PermissionLocation.locationFor(Identifier.VALET_MODE,
                PermissionLocation.Type.LIMITED), true);

        permissions.allow(PermissionLocation.locationFor(Identifier.WEATHER_CONDITIONS,
                PermissionLocation.Type.READ), true);
        permissions.allow(PermissionLocation.locationFor(Identifier.LIGHT_CONDITIONS,
                PermissionLocation.Type.READ), true); // these are the same - from environment

        permissions.allow(PermissionLocation.locationFor(Identifier.OFFROAD,
                PermissionLocation.Type.READ), true); // these are the same - from environment

        permissions.allow(PermissionLocation.locationFor(Identifier.NOTIFICATIONS,
                PermissionLocation.Type.READ), true);
        permissions.allow(PermissionLocation.locationFor(Identifier.NAVI_DESTINATION,
                PermissionLocation.Type.WRITE), true);

        // [0] - 0x10 - type autoAPI
        // [1] - 0x07 - 00000111 - all enabled
        // [2] - 0x18 - 00011000 - door locks enabled
        // [9] - 0x80 - 10000000 - tachograph read enabled
        assertTrue(permissions.equals("1007180000108220109800"));
    }

    @Test public void testCarRentalInit() {
        CarRentalPermissions permissions = new CarRentalPermissions();

        // base permissions methods
        permissions.allowCertificatesRead(true);
        permissions.allowCertificatesWrite(true);

        // custom car rental methods
        permissions.allowAutoApiRead(true);
        permissions.allowAutoApiWrite(true);
        permissions.allowDoorLocksWrite(true);
        permissions.allowEngineWrite(true);
        permissions.allowTheftAlarmWrite(true);
        permissions.setBookingIdentifier(new CarRentalBookingIdentifier("111111111111"));
        assertTrue(permissions.equals("20031f00000000000000111111111111"));
    }
}