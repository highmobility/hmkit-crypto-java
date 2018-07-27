package com.highmobility.test;

import com.highmobility.crypto.AccessCertificate;
import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.HMCalendar;
import com.highmobility.crypto.value.Issuer;
import com.highmobility.crypto.value.Permissions;
import com.highmobility.crypto.value.PublicKey;
import com.highmobility.crypto.value.Signature;
import com.highmobility.value.Bytes;

import org.junit.Before;
import org.junit.Test;

import java.util.Calendar;

import static org.junit.Assert.assertTrue;

public class V1AccessCertificateTest {
    AccessCertificate certificate;
    Bytes certBytes = new Bytes
            ("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000607010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");
    Bytes certBytesNoSignature = new Bytes
            ("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000607010203070804050609090A0A0A0A0A0A0A0A0A");

    @Before public void setUp() {
        certificate = new AccessCertificate(certBytes);
    }

    @Test public void certificateData() {
        assertTrue(certificate.getCertificateData().equals(certBytesNoSignature));
    }

    @Test public void fullData() {
        assertTrue(certificate.getBytes().equals(certBytes));
    }

    @Test public void testGetIssuer() {
        Bytes bytes = new Bytes("03000003");
        assertTrue(bytes.equals(certificate.getIssuer()));
    }

    @Test public void testGetProviderSerial() {
        DeviceSerial serial = new DeviceSerial("040000000000000004");
        assertTrue(certificate.getProviderSerial().equals(serial));
    }

    @Test public void testGetGainerSerial() {
        DeviceSerial serial = new DeviceSerial("050000000000000005");
        assertTrue(certificate.getGainerSerial().equals(serial));
    }

    @Test public void testGetGainerPublicKey() {
        PublicKey publicKey = new PublicKey
                ("06000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006");
        assertTrue(certificate.getGainerPublicKey().equals(publicKey));
    }

    @Test public void testGetStartDate() {
        Calendar date = certificate.getStartDate().getCalendar();

        assertTrue(date.get(Calendar.YEAR) == 2007);
        assertTrue(date.get(Calendar.MONTH) == 0);
        assertTrue(date.get(Calendar.DAY_OF_MONTH) == 2);
        assertTrue(date.get(Calendar.HOUR) == 3);
        assertTrue(date.get(Calendar.MINUTE) == 7);
    }

    @Test public void testGetStartDateBytes() {
        Bytes date = new Bytes("0701020307");
        assertTrue(certificate.getStartDate().equals(date));
    }

    @Test public void testGetEndDate() {
        Calendar date = certificate.getEndDate().getCalendar();

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
        Bytes date = new Bytes("0804050609");
        assertTrue(certificate.getEndDate().equals(date));
    }

    @Test public void testGetPermissions() {
        Permissions permissions = new Permissions("0A0A0A0A0A0A0A0A0A");
        assertTrue(certificate.getPermissions().equals(permissions));
        assertTrue(certificate.getPermissions().getLength() == 9);
    }

    @Test public void testSetPermissions() {
        Permissions newPermissions = new Permissions("0D0D");
        assertTrue(certificate.getPermissions().equals(newPermissions) == false);
        // set new permissions
        certificate.setPermissions(newPermissions);
        assertTrue(certificate.getPermissions().getLength() == 2);
        assertTrue(certificate.getPermissions().equals(newPermissions));

        Bytes expectedBytes = new Bytes
                ("01030000030400000000000000040500000000000000050600000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000607010203070804050609020D0D");
        Bytes newBytes = certificate.getCertificateData();
        assertTrue(newBytes.equals(expectedBytes));

        // set new signature
        assertTrue(certificate.getSignature() == null);
        certificate.setSignature(new Signature
                ("DDEE000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000D"));
        assertTrue(certificate.getSignature().equals
                ("DDEE000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000D"));

        // all of the other values must stay the same
        testGetIssuer();
        testGetProviderSerial();
        testGetGainerSerial();
        testGetGainerPublicKey();
        testGetStartDate();
        testGetStartDateBytes();
        testGetEndDate();
        testGetEndDateBytes();
    }

    @Test public void testIsExpired() {
        assertTrue(certificate.isExpired() == true);
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
        Signature sig = new Signature
                ("0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");
        assertTrue(certificate.getSignature().equals(sig));
    }

    @Test public void testSetSignature() {
        Signature newSig = new Signature
                ("0D00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000D");
        assertTrue(certificate.getSignature().equals(newSig) == false);
        certificate.setSignature(newSig);
        assertTrue(certificate.getSignature().equals(newSig));
    }

    @Test public void testBase64() {
        Bytes bytesObject = new Bytes
                ("AXRtY3Ne6l/0QGHF3aUE2YKllVOCcErgcuJtF3YJbV" +
                        "//WSqLZ04w29OuyQDz5RwE0dkM8z39OHNKFcCg9U" +
                        "//ZB66IMZlZDaM60zfdXT5HMXWSK28RMufEgMUDA0bAQEPERAQB//9" +
                        "/+////8DAAAAAAAA6bYOk2i5i5hySCxt8KA7rUwrawkhXu5oqRhQjKVDU179owJ3wkbiAOjUzcVbnCoiSCL6+t1VX2zFN522jt8c3g==");
        AccessCertificate cert = new AccessCertificate(bytesObject);
        System.out.println(cert);
    }

    @Test public void testObjectsConstructor() {
        // 01746D63735EEA5FF44061C5DDA504D982A5955382704AE072E26D1776096D5FFF592A8B674E30DBD3AEC900F3E51C04D1D90CF33DFD38734A15C0A0F54FFF641EBA20C66564368CEB4CDF7574F91CC5D648ADBC44CB9F1203140C0D1B01010F11101007FFFDFFEFFFFFFF03000000000000E9B60E9368B98B9872482C6DF0A03BAD4C2B6B09215EEE68A918508CA543535EFDA30277C246E200E8D4CDC55B9C2A224822FAFADD555F6CC5379DB68EDF1CDE
        AccessCertificate cert = new AccessCertificate(
                new Issuer("746D6373"),
                new DeviceSerial("5EEA5FF44061C5DDA5"),
                new DeviceSerial("04D982A5955382704A"),
                new PublicKey
                        ("E072E26D1776096D5FFF592A8B674E30DBD3AEC900F3E51C04D1D90CF33DFD38734A15C0A0F54FFF641EBA20C66564368CEB4CDF7574F91CC5D648ADBC44CB9F"),
                new HMCalendar("1203140C0D"),
                new HMCalendar("1B01010F11"),
                new Permissions("1007FFFDFFEFFFFFFF03000000000000")
        );

        assertTrue(cert.getBytes().equals
                ("01746D63735EEA5FF44061C5DDA504D982A5955382704AE072E26D1776096D5FFF592A8B674E30DBD3AEC900F3E51C04D1D90CF33DFD38734A15C0A0F54FFF641EBA20C66564368CEB4CDF7574F91CC5D648ADBC44CB9F1203140C0D1B01010F11101007FFFDFFEFFFFFFF03000000000000"));

        cert.setSignature(new Signature
                ("E9B60E9368B98B9872482C6DF0A03BAD4C2B6B09215EEE68A918508CA543535EFDA30277C246E200E8D4CDC55B9C2A224822FAFADD555F6CC5379DB68EDF1CDE"));
        assertTrue(cert.getBytes().equals
                ("01746D63735EEA5FF44061C5DDA504D982A5955382704AE072E26D1776096D5FFF592A8B674E30DBD3AEC900F3E51C04D1D90CF33DFD38734A15C0A0F54FFF641EBA20C66564368CEB4CDF7574F91CC5D648ADBC44CB9F1203140C0D1B01010F11101007FFFDFFEFFFFFFF03000000000000E9B60E9368B98B9872482C6DF0A03BAD4C2B6B09215EEE68A918508CA543535EFDA30277C246E200E8D4CDC55B9C2A224822FAFADD555F6CC5379DB68EDF1CDE"));
    }
}