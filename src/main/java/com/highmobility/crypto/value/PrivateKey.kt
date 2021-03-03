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

import com.highmobility.crypto.CURVE_SPEC
import com.highmobility.crypto.JavaPrivateKey
import com.highmobility.crypto.KEY_GEN_ALGORITHM
import com.highmobility.utils.Base64
import com.highmobility.value.Bytes
import com.highmobility.value.BytesWithLength
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import com.highmobility.crypto.toBytes
import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec

/**
 * 32 bytes of the EC private key in ANSI X9.62. Absolute value of the BigInteger
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
        this.bytes = javaKey.getBytes().byteArray
    }

    fun toJavaKey(): BCECPrivateKey {
        val kecFactory = KeyFactory.getInstance(KEY_GEN_ALGORITHM, "BC")
        val d = BigInteger(1, byteArray)
        val privateKeySpec = ECPrivateKeySpec(d, CURVE_SPEC)
        return kecFactory.generatePrivate(privateKeySpec) as BCECPrivateKey
    }

    override fun getExpectedLength(): Int {
        return 32
    }

    companion object {
        fun fromPKCS8(serviceAccountApiPrivateKey: String): PrivateKey {
            var encodedKeyString = serviceAccountApiPrivateKey
            // TODO: 19/2/21 try to use BC PKCS8 methods to not remove these strings manually
            encodedKeyString = encodedKeyString.replace("-----BEGIN PRIVATE KEY----", "")
            encodedKeyString = encodedKeyString.replace("-----END PRIVATE KEY-----", "")
            val decodedPrivateKey = Base64.decode(encodedKeyString)
            val keySpec = PKCS8EncodedKeySpec(decodedPrivateKey)
            // how to convert PKCS#8 to EC private key https://stackoverflow.com/a/52301461/599743
            val kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM, "BC")
            return PrivateKey(kf.generatePrivate(keySpec) as BCECPrivateKey)
        }
    }
}

fun JavaPrivateKey.getBytes(): Bytes {
    val d = (this as BCECPrivateKey).d
    return Bytes(d.toBytes(32))
}