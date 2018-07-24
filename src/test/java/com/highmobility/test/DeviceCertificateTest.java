package com.highmobility.test;

import com.highmobility.crypto.DeviceCertificate;
import com.highmobility.crypto.value.AppIdentifier;
import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.Issuer;
import com.highmobility.crypto.value.PublicKey;
import com.highmobility.crypto.value.Signature;
import com.highmobility.utils.Base64;
import com.highmobility.value.Bytes;

import org.junit.Test;

import static junit.framework.TestCase.assertTrue;

public class DeviceCertificateTest {
    Issuer issuer = new Issuer("00000000");
    AppIdentifier appIdentifier = new AppIdentifier("111111111111111111111111");
    DeviceSerial serial = new DeviceSerial("222222222222222222");
    PublicKey publicKey = new PublicKey
            ("33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333");
    Signature signature = new Signature
            ("44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444");

    Bytes bytes = new Bytes(issuer.getHex() +
            appIdentifier.getHex() +
            serial.getHex() +
            publicKey.getHex() +
            signature.getHex());

    Bytes bytesWithOutSignature = new Bytes(issuer.getHex() +
            appIdentifier.getHex() +
            serial.getHex() +
            publicKey.getHex());

    @Test public void ctorWithBytes() {
        DeviceCertificate cert = new DeviceCertificate(bytes);
        assertTrue(cert.getIssuer().equals(issuer));
        assertTrue(cert.getAppIdentifier().equals(appIdentifier));
        assertTrue(cert.getSerial().equals(serial));
        assertTrue(cert.getPublicKey().equals(publicKey));
        assertTrue(cert.getSignature().equals(signature));
        assertTrue(cert.getCertificateData().equals(bytesWithOutSignature));
    }

    @Test public void ctorWithVars() {
        DeviceCertificate cert = new DeviceCertificate(issuer, appIdentifier, serial, publicKey);
        assertTrue(cert.getBytes().equals(bytesWithOutSignature));
        cert.setSignature(signature);
        assertTrue(cert.getBytes().equals(bytes));
        assertTrue(cert.getCertificateData().equals(bytesWithOutSignature));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateThrows() {
        String hex =
                "53495854636F6D2E736978742E6F6E65C859C2B5C11C7CA8E3C3DD65187BC49E53D5C2E2212037F37E72487709DBF0DFB60A73F86092113C92EECA5D3E01EE9C892AF53C2A5E3144E35824D607C0C84C7C2176C44EA3D0D6C7A6D170DDF976FDBA86EFA8E52E607738CD456779452E7374949282225C1C4B3DD5CD591CBA0E77E9A5E298113A32F965ABE7FA70982CAAE6FB2C854D599DD5C7";
        new DeviceCertificate(new Bytes(Base64.decode(hex)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateThrowsCertHasMoreBytes() {
        String hex = "U0lYVGNvbS5zaXh0Lm9uZSYkwo02A4OvXScF9wE" +
                "/poYh3t7ED288tUdHj5Rpnoq3bA1ds0z3eCQieBQQk3xFQDi6Jh/xSq3YTOnxNJxPfpv7RXRqfh" +
                "+yI0cm3IYwiSLu5mI/4GyE23qLEl/E69g8VvCA4My1PgE0WZCQF477ltQhAW8MNPi" +
                "+arRyMU7jiCaWWNhteqMDDKPoqg==";
        new DeviceCertificate(new Bytes(Base64.decode(hex)));
    }

    @Test public void testValidateDoesNotThrowForCorrectInput() {
        String base64 = "U0lYVGNvbS5zaXh0Lm9uZSYkwo02A4OvXScF9wE" +
                "/poYh3t7ED288tUdHj5Rpnoq3bA1ds0z3eCQieBQQk3xFQDi6Jh/xSq3YTOnxNJxPfpv7RXRqfh" +
                "+yI0cm3IYwiSLu5mI/4GyE23qLEl/E69g8VvCA4My1PgE0WZCQF477ltQhAW8MNPi" +
                "+arRyMU7jiCaWWNhteqMDDKPo";
        new DeviceCertificate(new Bytes(Base64.decode(base64))); // correct

        String hex89bytes =
                "53495854636F6D2E736978742E6F6E652624C28D360383AF5D2705F7013FA68621DEDEC40F6F3CB547478F94699E8AB76C0D5DB34CF7782422781410937C454038BA261FF14AADD84CE9F1349C4F7E9BFB45746A7E1FB22347";
        new DeviceCertificate(new Bytes(hex89bytes)); // correct
    }

}