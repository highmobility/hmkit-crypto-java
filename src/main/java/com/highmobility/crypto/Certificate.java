/*
 * HMKit Crypto - Crypto for Java
 * Copyright (C) 2018 High-Mobility <licensing@high-mobility.com>
 *
 * This file is part of HMKit Crypto.
 *
 * HMKit Crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HMKit Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HMKit Crypto.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.highmobility.crypto;

import com.highmobility.value.Bytes;
import com.highmobility.value.Signature;

/**
 * Created by ttiganik on 13/04/16.
 */
public class Certificate {
    Bytes bytes;

    Signature signature;
    Bytes certificateData;

    Certificate(Bytes bytes) {
        this.bytes = bytes;
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
            this.bytes = getCertificateData();
        } else {
            this.bytes = Bytes.concat(getCertificateData(), signature);
        }

        this.signature = signature;
    }

    /**
     * @return The full certificate bytes. This includes the signature, if exists.
     */
    public Bytes getBytes() {
        return bytes;
    }

    /**
     * @return The raw bytes encoded in base64.
     * @deprecated use {@link #getBytes()} instead
     */
    @Deprecated
    public String getBase64() {
        return bytes.getBase64();
    }
}
