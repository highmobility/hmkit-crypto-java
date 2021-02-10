package com.highmobility.crypto.value

import CURVE_NAME
import JavaPublicKey
import com.highmobility.value.Bytes
import com.highmobility.value.BytesWithLength
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import toBytes
import java.security.KeyFactory

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

    constructor(javaKey: BCECPublicKey) {
        val W = (javaKey as BCECPublicKey).q
        val WX = W.affineXCoord
        val WY = W.affineYCoord

        val xBytes = WX.toBigInteger().toBytes()
        val yBytes = WY.toBigInteger().toBytes()
        val bytes = xBytes.concat(yBytes)

        this.bytes = bytes.byteArray
    }

    override fun getExpectedLength(): Int {
        return 64
    }

    fun toJavaKey(): BCECPublicKey {
        val rawKeyEncoded = Bytes("04").concat(this).byteArray

        val params = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        val keySpec = ECPublicKeySpec(params.curve.decodePoint(rawKeyEncoded), params)
        val publicKey = BCECPublicKey("ECDSA", keySpec, BouncyCastleProvider.CONFIGURATION)
        return publicKey
    }

    // this is from x509
    private fun x509toJavaPublicKey(byteArray: ByteArray): BCECPublicKey {
        // TODO: 9/2/21 maybe add 04 byte in from to get DER encoding
        val bpubKey = PublicKeyFactory.createKey(byteArray) as ECPublicKeyParameters
        val kf = KeyFactory.getInstance("EC", "BC")
        val spec = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        return kf.generatePublic(
            ECPublicKeySpec(
                bpubKey.q,
                spec
            )
        ) as BCECPublicKey
    }
}

fun JavaPublicKey.getBytes(): Bytes {
    val W = (this as BCECPublicKey).q
    val WX = W.affineXCoord
    val WY = W.affineYCoord

    val xBytes = WX.toBigInteger().toBytes()
    val yBytes = WY.toBigInteger().toBytes()
    val bytes = xBytes.concat(yBytes)
    return bytes
}