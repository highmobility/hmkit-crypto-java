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
package com.highmobility.crypto.value

import com.highmobility.value.Bytes
import com.highmobility.value.BytesWithLength
import java.math.BigInteger
import org.bouncycastle.asn1.ASN1Encoding

import org.bouncycastle.asn1.DERSequence

import org.bouncycastle.asn1.ASN1Integer

import org.bouncycastle.asn1.ASN1EncodableVector

/**
 * Raw 64 bytes of r and s components of the ECDSA signature with sha256 - ASN.1. P1363 format.
 * Java signature is ASN.1 DER
 */
class Signature : BytesWithLength {
    /**
     * @param value The raw bytes.
     */
    constructor(value: Bytes?) : super(value)

    /**
     * @param value The bytes in hex or Base64.
     */
    constructor(value: String?) : super(value)

    /**
     * @param bytes The raw bytes.
     */
    constructor(bytes: ByteArray?) : super(bytes)

    override fun getExpectedLength(): Int {
        return 64
    }

    fun getR(): BigInteger {
        return BigInteger(1, subList(0, 32).toByteArray())
    }

    fun getS(): BigInteger {
        return BigInteger(1, subList(32, 64).toByteArray())
    }

    // 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
    fun derEncoded(): ByteArray {
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(getR()))
        v.add(ASN1Integer(getS()))
        val derEncodedSignature = DERSequence(v).getEncoded(ASN1Encoding.DER)
        return derEncodedSignature
    }
}