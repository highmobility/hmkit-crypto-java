package com.highmobility.crypto;

import com.highmobility.utils.Bytes;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Calendar;

import static org.junit.Assert.*;

public class AccessCertificateTest {
    AccessCertificate v1certificate;
    byte[] v1certificateBytes = Bytes.bytesFromHex("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000607010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");

    AccessCertificate v0certificate;
    byte[] v0certificateBytes = Bytes.bytesFromHex("05000000000000000506060000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006A62D4B2D4E8502147007010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");

    @Before public void setUp() throws Exception {
        v1certificate = new AccessCertificate(v1certificateBytes);
        v0certificate = new AccessCertificate(v0certificateBytes);
    }

    @Test public void testGetIssuer() throws Exception {
        byte[] bytes = new byte[] {0x03, 0x00, 0x00, 0x03};
        assertTrue(Arrays.equals(bytes, v1certificate.getIssuer()));
    }

    @Test public void testv0GetIssuer() throws Exception {
        assertTrue(Arrays.equals(
                Bytes.bytesFromHex("746D6373"),
                v0certificate.getIssuer()));
    }

    @Test public void testGetProviderSerial() throws Exception {
        byte[] bytes = new byte[] { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };
        assertTrue(Arrays.equals(bytes, v1certificate.getProviderSerial()));
    }

    @Test public void testv0GetProviderSerial() throws Exception {
        String provider = Bytes.hexFromBytes(v0certificate.getProviderSerial());

        assertTrue(Arrays.equals(
                Bytes.bytesFromHex("A62D4B2D4E85021470"),
                v0certificate.getProviderSerial()));
    }

    @Test public void testGetGainerSerial() throws Exception {
        byte[] bytes = new byte[] { 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };
        assertTrue(Arrays.equals(bytes, v1certificate.getGainerSerial()));
    }

    @Test public void testv0GetGainerSerial() throws Exception {
        String gainer = Bytes.hexFromBytes(v0certificate.getGainerSerial());

        assertTrue(Arrays.equals(
                Bytes.bytesFromHex("050000000000000005"),
                v0certificate.getGainerSerial()));
    }

    @Test public void testGetGainerPublicKey() throws Exception {
        byte[] bytes = new byte[] { 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 };
        assertTrue(Arrays.equals(bytes, v1certificate.getGainerPublicKey()));
    }

    @Test public void testv0GetGainerPublicKey() throws Exception {
        String publicKey = Bytes.hexFromBytes(v0certificate.getGainerPublicKey());

        assertTrue(Arrays.equals(
                Bytes.bytesFromHex("06060000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006"),
                v0certificate.getGainerPublicKey()));
    }

    @Test public void testGetStartDate() throws Exception {
        Calendar date = v1certificate.getStartDate();

        assertTrue(date.get(Calendar.YEAR) == 2007);
        assertTrue(date.get(Calendar.MONTH) == 0);
        assertTrue(date.get(Calendar.DAY_OF_MONTH) == 2);
        assertTrue(date.get(Calendar.HOUR) == 3);
        assertTrue(date.get(Calendar.MINUTE) == 7);
    }

    @Test public void testGetStartDateBytes() throws Exception {
        byte[] bytes = new byte[] { 0x07, 0x01, 0x02, 0x03, 0x07 };
        assertTrue(Arrays.equals(bytes, v1certificate.getStartDateBytes()));
    }

    @Test public void testGetEndDate() throws Exception {
        Calendar date = v1certificate.getEndDate();

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

    @Test public void testGetEndDateBytes() throws Exception {
        byte[] bytes = new byte[] { 0x08, 0x04, 0x05, 0x06, 0x09 };
        assertTrue(Arrays.equals(bytes, v1certificate.getEndDateBytes()));
    }

    @Test public void testGetPermissions() throws Exception {
        assertTrue(v1certificate.getPermissions().length == 9);

        byte[] bytes = new byte[] { 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A };
        byte[] permissions = v1certificate.getPermissions();
        assertTrue(Arrays.equals(bytes, permissions));
    }

    @Test public void testSetPermissions() throws Exception {
        byte[] newPermissions = new byte[] { 0x0D, 0x0D };
        assertTrue(Arrays.equals(v1certificate.getPermissions(), newPermissions) == false);
        v1certificate.setPermissions(newPermissions);
        assertTrue(v1certificate.getPermissions().length == 2);
        assertTrue(Arrays.equals(v1certificate.getPermissions(), newPermissions) == true);

        // new signature will be null
        assertTrue(v1certificate.getSignature() == null);
        byte[] newSig = new byte[] {(byte) 0xDD, (byte) 0xEE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D };
        v1certificate.setSignature(newSig);
        assertTrue(Arrays.equals(v1certificate.getSignature(), newSig) == true);
    }

    @Test public void testIsExpired() throws Exception {
        assertTrue(v1certificate.isExpired() == true);
    }

    @Test public void testIsNotValidYet() throws Exception {
        byte[] bytes = Bytes.bytesFromHex("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000663010203076304050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");
        AccessCertificate cert = new AccessCertificate(bytes);
        assertTrue(cert.isNotValidYet());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testThrowsWhenEndDateSoonerThanStartDate() throws Exception {
        byte[] bytes = Bytes.bytesFromHex("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000663050203076304050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");
        AccessCertificate cert = new AccessCertificate(bytes);
    }

    @Test public void testGetSignature() throws Exception {
        byte[] bytes = new byte[] { 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B };
        assertTrue(Arrays.equals(bytes, v1certificate.getSignature()));
    }

    @Test public void testSetSignature() throws Exception {
        byte[] newSig = new byte[] { 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D };
        assertTrue(Arrays.equals(v1certificate.getSignature(), newSig) == false);
        v1certificate.setSignature(newSig);
        assertTrue(Arrays.equals(v1certificate.getSignature(), newSig) == true);
    }

}