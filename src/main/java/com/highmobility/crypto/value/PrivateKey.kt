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

import com.highmobility.crypto.*
import com.highmobility.utils.Base64
import com.highmobility.value.Bytes
import com.highmobility.value.BytesWithLength
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec

/**
 * 32 bytes of the EC private key in ANSI X9.62. Absolute value of the BigInteger
 */
class PrivateKey : BytesWithLength {
    /**
     * @param value The raw bytes.
     */
    constructor(value: Bytes?) : super(value)

    /**
     * @param value The private key value
     * @param format The value format. For raw, it is 32 bytes in hex or base64
     */
    constructor(value: String, format: Format = Format.RAW) : super(resolve(value, format))

    /**
     * @param bytes The raw bytes.
     */
    constructor(bytes: ByteArray?) : super(bytes)

    constructor(javaKey: ECPrivateKey) {
        this.bytes = javaKey.getBytes().byteArray
    }

    fun toJavaKey(): ECPrivateKey {
        Crypto.setProvider()
        val keyFactory = KeyFactory.getInstance(KEY_GEN_ALGORITHM, "BC")
        val d = BigInteger(1, byteArray)
        val privateKeySpec = ECPrivateKeySpec(d, CURVE_SPEC)
        return keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
    }

    override fun getExpectedLength(): Int {
        return 32
    }

    companion object {
        private fun resolve(value: String, format: Format = Format.RAW): Bytes {
            return if (format == Format.RAW) {
                Bytes(value)
            } else {
                fromPKCS8(value).getBytes()
            }
        }

        private fun fromPKCS8(privateKey: String): ECPrivateKey {
            Crypto.setProvider()
            var encodedKeyString = privateKey
            // NOTE: 19/2/21 there are BC PKCS8 convert methods that remove these strings also
            encodedKeyString = encodedKeyString.replace("-----BEGIN PRIVATE KEY----", "")
            encodedKeyString = encodedKeyString.replace("-----END PRIVATE KEY-----", "")
            val decodedPrivateKey = Base64.decode(encodedKeyString)
            val keySpec = PKCS8EncodedKeySpec(decodedPrivateKey)
            // how to convert PKCS#8 to EC private key https://stackoverflow.com/a/52301461/599743
            val kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM, "BC")
            return kf.generatePrivate(keySpec) as ECPrivateKey
        }
    }

    enum class Format { RAW, PKCS8 }
}

fun JavaPrivateKey.getBytes(): Bytes {
    val d = (this as ECPrivateKey).s
    return Bytes(d.toBytes(32))
}