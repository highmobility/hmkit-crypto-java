package com.highmobility.crypto;

import com.highmobility.utils.Bytes;

import junit.framework.TestCase;

import java.util.Arrays;
import java.util.Calendar;

public class AccessCertificateTest extends TestCase {
    AccessCertificate certificate;
    byte[] certificateBytes = Bytes.bytesFromHex("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000607010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");

    public void setUp() throws Exception {
        certificate = new AccessCertificate(certificateBytes);
        super.setUp();
    }

    public void testV0() {
        byte[] v0Bytes = Bytes.bytesFromHex("05000000000000000506000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006A62D4B2D4E8502147007010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");
        AccessCertificate cert = new AccessCertificate(v0Bytes);
        assertTrue(Arrays.equals(cert.getGainerSerial(), Bytes.bytesFromHex("050000000000000005")));
    }

    public void testGetIssuer() throws Exception {
        byte[] bytes = new byte[] {0x03, 0x00, 0x00, 0x03};
        assertTrue(Arrays.equals(bytes, certificate.getIssuer()));
    }

    public void testGetProviderSerial() throws Exception {
        byte[] bytes = new byte[] { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };
        assertTrue(Arrays.equals(bytes, certificate.getProviderSerial()));
    }

    public void testGetGainerSerial() throws Exception {
        byte[] bytes = new byte[] { 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };
        assertTrue(Arrays.equals(bytes, certificate.getGainerSerial()));
    }

    public void testGetGainerPublicKey() throws Exception {
        byte[] bytes = new byte[] { 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 };
        assertTrue(Arrays.equals(bytes, certificate.getGainerPublicKey()));
    }

    public void testGetStartDate() throws Exception {
        Calendar date = certificate.getStartDate();

        assertTrue(date.get(Calendar.YEAR) == 2007);
        assertTrue(date.get(Calendar.MONTH) == 0);
        assertTrue(date.get(Calendar.DAY_OF_MONTH) == 2);
        assertTrue(date.get(Calendar.HOUR) == 3);
        assertTrue(date.get(Calendar.MINUTE) == 7);
    }

    public void testGetStartDateBytes() throws Exception {
        byte[] bytes = new byte[] { 0x07, 0x01, 0x02, 0x03, 0x07 };
        assertTrue(Arrays.equals(bytes, certificate.getStartDateBytes()));
    }

    public void testGetEndDate() throws Exception {
        Calendar date = certificate.getEndDate();

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

    public void testGetEndDateBytes() throws Exception {
        byte[] bytes = new byte[] { 0x08, 0x04, 0x05, 0x06, 0x09 };
        assertTrue(Arrays.equals(bytes, certificate.getEndDateBytes()));
    }

    public void testGetPermissions() throws Exception {
        assertTrue(certificate.getPermissions().length == 9);

        byte[] bytes = new byte[] { 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A };
        byte[] permissions = certificate.getPermissions();
        assertTrue(Arrays.equals(bytes, permissions));
    }

    public void testSetPermissions() throws Exception {
        byte[] newPermissions = new byte[] { 0x0D, 0x0D };
        assertTrue(Arrays.equals(certificate.getPermissions(), newPermissions) == false);
        certificate.setPermissions(newPermissions);
        assertTrue(certificate.getPermissions().length == 2);
        assertTrue(Arrays.equals(certificate.getPermissions(), newPermissions) == true);

        // new signature will be null
        assertTrue(certificate.getSignature() == null);
        byte[] newSig = new byte[] {(byte) 0xDD, (byte) 0xEE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D };
        certificate.setSignature(newSig);
        assertTrue(Arrays.equals(certificate.getSignature(), newSig) == true);
    }

    public void testIsExpired() throws Exception {
        assertTrue(certificate.isExpired() == true);
    }

    public void testGetSignature() throws Exception {
        byte[] bytes = new byte[] { 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B };
        assertTrue(Arrays.equals(bytes, certificate.getSignature()));
    }

    public void testSetSignature() throws Exception {
        byte[] newSig = new byte[] { 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D };
        assertTrue(Arrays.equals(certificate.getSignature(), newSig) == false);
        certificate.setSignature(newSig);
        assertTrue(Arrays.equals(certificate.getSignature(), newSig) == true);
    }

}