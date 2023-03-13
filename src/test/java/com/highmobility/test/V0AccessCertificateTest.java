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
package com.highmobility.test;

import com.highmobility.crypto.AccessCertificate;
import com.highmobility.crypto.value.Issuer;
import com.highmobility.value.Bytes;
import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.PublicKey;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class V0AccessCertificateTest {
    AccessCertificate v0certificate;
    Bytes v0certificateBytes = new Bytes
            ("05000000000000000506060000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006A62D4B2D4E8502147007010203070804050609090A0A0A0A0A0A0A0A0A0B00000000000000000600000000000006000000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000B");

    @Before public void setUp() {
        v0certificate = new AccessCertificate(v0certificateBytes);
    }

    @Test public void testv0GetIssuer() {
        Issuer issuer = new Issuer("746D6373");
        assertTrue(v0certificate.getIssuer().equals(issuer));
    }

    @Test public void testv0GetProviderSerial() {
        DeviceSerial serial = new DeviceSerial("A62D4B2D4E85021470");
        assertTrue(serial.equals(v0certificate.getProviderSerial()));
    }

    @Test public void testv0GetGainerSerial() {
        DeviceSerial serial = new DeviceSerial("050000000000000005");
        assertTrue(v0certificate.getGainerSerial().equals(serial));
    }

    @Test public void testv0GetGainerPublicKey() {
        PublicKey publicKey = new PublicKey
                ("06060000000000000006000000000000060000000000000000060000000000000600000000000000000600000000000006000000000000000006000000000006");
        assertTrue(v0certificate.getGainerPublicKey().equals(publicKey));
    }
}