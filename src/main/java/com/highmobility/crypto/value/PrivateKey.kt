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
package com.highmobility.crypto.value

import CURVE
import CURVE_SPEC
import JavaPrivateKey
import com.highmobility.value.Bytes
import com.highmobility.value.BytesWithLength
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import toBytes
import java.math.BigInteger
import java.security.KeyFactory

/**
 * 32 bytes of the EC private key in ANSI X9.62.
 */
class PrivateKey : BytesWithLength {
    /**
     * @param value The raw bytes.
     */
    constructor(value: Bytes?) : super(value) {}

    /**
     * @param value The bytes in hex or Base64.
     */
    constructor(value: String?) : super(value) {}

    /**
     * @param bytes The raw bytes.
     */
    constructor(bytes: ByteArray?) : super(bytes) {}

    constructor(javaKey: BCECPrivateKey) {
        val d = (javaKey as BCECPrivateKey).d
        this.bytes = d.toByteArray()
    }

    fun toJavaKey(): BCECPrivateKey {
        val kecFactory = KeyFactory.getInstance("EC", "BC")
        val generatedECPrivateKeyParams = ECPrivateKeyParameters(BigInteger(1, byteArray), CURVE)
        val privateKeySpec = ECPrivateKeySpec(generatedECPrivateKeyParams.d, CURVE_SPEC)

        val privateKey = kecFactory.generatePrivate(privateKeySpec)
        return privateKey as BCECPrivateKey
    }

    override fun getExpectedLength(): Int {
        return 32
    }
}

fun JavaPrivateKey.getBytes(): Bytes {
    val d = (this as BCECPrivateKey).d
    return Bytes(d.toBytes(32))
}