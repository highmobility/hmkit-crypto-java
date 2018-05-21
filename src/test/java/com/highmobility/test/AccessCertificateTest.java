package com.highmobility.test;

import com.highmobility.crypto.AccessCertificate;
import com.highmobility.value.Bytes;
import com.highmobility.value.DeviceSerial;
import com.highmobility.value.HMCalendar;
import com.highmobility.value.Issuer;
import com.highmobility.value.Permissions;
import com.highmobility.value.PublicKey;
import com.highmobility.value.Signature;

import org.junit.Before;
import org.junit.Test;

import java.util.Calendar;

import static org.junit.Assert.assertTrue;

public class AccessCertificateTest {
    AccessCertificate v1certificate;
    Bytes v1certificateBytes = new Bytes
            ("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000607010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");

    AccessCertificate v0certificate;
    Bytes v0certificateBytes = new Bytes
            ("05000000000000000506060000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006A62D4B2D4E8502147007010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");

    @Before public void setUp() {
        v1certificate = new AccessCertificate(v1certificateBytes);
        v0certificate = new AccessCertificate(v0certificateBytes);
    }

    @Test public void testGetIssuer() {
        Bytes bytes = new Bytes(new byte[]{0x03, 0x00, 0x00, 0x03});
        assertTrue(bytes.equals(v1certificate.getIssuer()));
    }

    @Test public void testv0GetIssuer() {
        Issuer issuer = new Issuer("746D6373");
        assertTrue(v0certificate.getIssuer().equals(issuer));
    }

    @Test public void testGetProviderSerial() {
        DeviceSerial serial = new DeviceSerial(new byte[]{0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04});
        assertTrue(v1certificate.getProviderSerial().equals(serial));
    }

    @Test public void testv0GetProviderSerial() {
        DeviceSerial serial = new DeviceSerial("A62D4B2D4E85021470");
        assertTrue(serial.equals(v0certificate.getProviderSerial()));
    }

    @Test public void testGetGainerSerial() {
        DeviceSerial serial = new DeviceSerial(new byte[]{0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x05});
        assertTrue(v1certificate.getGainerSerial().equals(serial));
    }

    @Test public void testv0GetGainerSerial() {
        DeviceSerial serial = new DeviceSerial("050000000000000005");
        assertTrue(v0certificate.getGainerSerial().equals(serial));
    }

    @Test public void testGetGainerPublicKey() {
        byte[] bytes = new byte[]{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x06};
        PublicKey publicKey = new PublicKey(bytes);
        PublicKey certPublicKey = v1certificate.getGainerPublicKey();
        assertTrue(v1certificate.getGainerPublicKey().equals(publicKey));
    }

    @Test public void testv0GetGainerPublicKey() {
        PublicKey publicKey = new PublicKey
                ("06060000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006");
        assertTrue(v0certificate.getGainerPublicKey().equals(publicKey));
    }

    @Test public void testGetStartDate() {
        Calendar date = v1certificate.getStartDate().getCalendar();

        assertTrue(date.get(Calendar.YEAR) == 2007);
        assertTrue(date.get(Calendar.MONTH) == 0);
        assertTrue(date.get(Calendar.DAY_OF_MONTH) == 2);
        assertTrue(date.get(Calendar.HOUR) == 3);
        assertTrue(date.get(Calendar.MINUTE) == 7);
    }

    @Test public void testGetStartDateBytes() {
        byte[] bytes = new byte[]{0x07, 0x01, 0x02, 0x03, 0x07};
        HMCalendar date = new HMCalendar(bytes);
        assertTrue(v1certificate.getStartDate().equals(date));
    }

    @Test public void testGetEndDate() {
        Calendar date = v1certificate.getEndDate().getCalendar();

        int year = date.get(Calendar.YEAR);
        int month = date.get(Calendar.MONTH);
        int day = date.get(Calendar.DAY_OF_MONTH);
        int hour = date.get(Calendar.HOUR);
        int minute = date.get(Calendar.MINUTE);

        assertTrue(year == 2008);
        assertTrue(month == 3);
        assertTrue(day == 5);
        assertTrue(hour == 6);
        assertTrue(minute == 9);
    }

    @Test public void testGetEndDateBytes() {
        byte[] bytes = new byte[]{0x08, 0x04, 0x05, 0x06, 0x09};
        HMCalendar date = new HMCalendar(bytes);
        assertTrue(v1certificate.getEndDate().equals(date));
    }

    @Test public void testGetPermissions() {
        byte[] bytes = new byte[]{0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A};
        Permissions permissions = new Permissions(bytes);
        assertTrue(v1certificate.getPermissions().equals(permissions));
        assertTrue(v1certificate.getPermissions().getLength() == 9);
    }

    @Test public void testSetPermissions() {
        Permissions newPermissions = new Permissions(new byte[]{0x0D, 0x0D});
        assertTrue(v1certificate.getPermissions().equals(newPermissions) == false);
        v1certificate.setPermissions(newPermissions);
        assertTrue(v1certificate.getPermissions().getLength() == 2);
        assertTrue(v1certificate.getPermissions().equals(newPermissions));

        // new signature will be null
        assertTrue(v1certificate.getSignature() == null);
        byte[] newSig = new byte[]{(byte) 0xDD, (byte) 0xEE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x0D};
        v1certificate.setSignature(new Signature("DDEE000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000D"));
        assertTrue(v1certificate.getSignature().equals(newSig));
    }

    @Test public void testIsExpired() {
        assertTrue(v1certificate.isExpired() == true);
    }

    @Test public void testIsNotValidYet() {
        Bytes bytes = new Bytes
                ("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000663010203076304050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");
        AccessCertificate cert = new AccessCertificate(bytes);
        assertTrue(cert.isNotValidYet());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testThrowsWhenEndDateSoonerThanStartDate() {
        Bytes bytes = new Bytes
                ("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000663050203076304050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");
        new AccessCertificate(bytes);
    }

    @Test public void testGetSignature() {
        byte[] bytes = new byte[]{0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x0B};
        Signature sig = new Signature(bytes);
        assertTrue(v1certificate.getSignature().equals(sig));
    }

    @Test public void testSetSignature() {
        byte[] bytes = new byte[]{0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x0D};
        Signature newSig = new Signature(bytes);

        assertTrue(v1certificate.getSignature().equals(newSig) == false);
        v1certificate.setSignature(newSig);
        assertTrue(v1certificate.getSignature().equals(newSig));
    }
}