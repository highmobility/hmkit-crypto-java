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

import com.highmobility.crypto.CURVE_NAME
import com.highmobility.crypto.JavaPublicKey
import com.highmobility.crypto.KEY_GEN_ALGORITHM
import com.highmobility.value.Bytes
import com.highmobility.value.BytesWithLength
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECPublicKeySpec
import com.highmobility.crypto.toBytes
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey

/**
 * Raw 32 byte x and y coordinates of the [CURVE_NAME] curve
 *
 */
class PublicKey : BytesWithLength {
    /**
     * @param value The raw bytes.
     */
    constructor(value: Bytes) : super(value)

    /**
     * @param value The bytes in hex or Base64.
     */
    constructor(value: String) : super(value)

    /**
     * @param bytes The raw bytes.
     */
    constructor(bytes: ByteArray) : super(bytes)

    constructor(javaKey: ECPublicKey) {
        this.bytes = javaKey.getBytes().byteArray
    }

    override fun getExpectedLength(): Int {
        return 64
    }

    fun toJavaKey(): ECPublicKey {
        val rawKeyEncoded = Bytes(65)
        rawKeyEncoded.set(0, 0x04)
        rawKeyEncoded.set(1, this)

        val params = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        val keySpec = ECPublicKeySpec(params.curve.decodePoint(rawKeyEncoded.byteArray), params)

        val keyFactory = KeyFactory.getInstance(KEY_GEN_ALGORITHM, "BC")
        val publicKey = keyFactory.generatePublic(keySpec) as ECPublicKey
        return publicKey
    }

    // this is from x509
    private fun x509toJavaPublicKey(byteArray: ByteArray): ECPublicKey {
        // maybe add 04 byte in from to get DER encoding
        val bpubKey = PublicKeyFactory.createKey(byteArray) as ECPublicKeyParameters
        val kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM, "BC")
        val spec = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        return kf.generatePublic(ECPublicKeySpec(bpubKey.q, spec)) as ECPublicKey
    }
}

fun JavaPublicKey.getBytes(): Bytes {
    val W = (this as ECPublicKey).w
    val WX = W.affineX
    val WY = W.affineY
    // sometimes 1 biginteger is 31 bytes long
    val xBytes = WX.toBytes(32)
    val yBytes = WY.toBytes(32)
    val bytes = xBytes.concat(yBytes)
    return bytes
}

fun JavaPublicKey.getParameters(): ECPublicKeyParameters {
    return ECUtil.generatePublicKeyParameter(this) as ECPublicKeyParameters
}
