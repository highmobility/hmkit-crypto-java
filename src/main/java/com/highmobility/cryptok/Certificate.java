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
package com.highmobility.cryptok;

import com.highmobility.cryptok.value.Signature;
import com.highmobility.value.Bytes;

/**
 * Base Certificate class.
 */
public class Certificate extends Bytes {
    Signature signature;
    Bytes certificateData;

    protected Certificate(int length) {
        super(length);
    }

    Certificate(Bytes bytes) {
        super(bytes);
    }

    Certificate() {
    }

    /**
     * @return The certificate data, excluding the signature.
     */
    public Bytes getCertificateData() {
        return certificateData;
    }

    /**
     * @return The Certificate Authority's signature for the certificate, 64 bytes.
     */
    public Signature getSignature() {
        return signature;
    }

    /**
     * Set a new signature or override the previous one.
     *
     * @param signature The new signature.
     */
    public void setSignature(Signature signature) {
        // all of the ivars stay the same, only the last signature bytes of the cert change.
        if (signature == null) {
            this.bytes = getCertificateData().getByteArray();
        } else {
            this.bytes = Bytes.concat(getCertificateData(), signature).getByteArray();
        }

        this.signature = signature;
    }
}
