package com.highmobility.test;

import com.highmobility.crypto.DeviceCertificate;
import com.highmobility.value.AppIdentifier;
import com.highmobility.value.Bytes;
import com.highmobility.value.DeviceSerial;
import com.highmobility.value.Issuer;
import com.highmobility.value.PublicKey;
import com.highmobility.value.Signature;

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
    @Test public void ctorWithBytes() {

        DeviceCertificate cert = new DeviceCertificate(bytes);
        assertTrue(cert.getIssuer().equals(issuer));
        assertTrue(cert.getAppIdentifier().equals(appIdentifier));
        assertTrue(cert.getSerial().equals(serial));
        assertTrue(cert.getPublicKey().equals(publicKey));
        assertTrue(cert.getSignature().equals(signature));

    }

    @Test public void ctorWithVars() {
        DeviceCertificate cert = new DeviceCertificate(issuer, appIdentifier, serial, publicKey);
        cert.setSignature(signature);

        assertTrue(cert.getBytes().equals(bytes));
    }
}