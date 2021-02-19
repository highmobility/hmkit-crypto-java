package com.highmobility.cryptok.value

import CURVE_NAME
import JavaPublicKey
import KEY_GEN_ALGORITHM
import com.highmobility.value.Bytes
import com.highmobility.value.BytesWithLength
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
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
        this.bytes = javaKey.getBytes().byteArray
    }

    override fun getExpectedLength(): Int {
        return 64
    }

    fun toJavaKey(): BCECPublicKey {
        val rawKeyEncoded = Bytes(65)
        rawKeyEncoded.set(0, 0x04)
        rawKeyEncoded.set(1, this)

        val params = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        val keySpec = ECPublicKeySpec(params.curve.decodePoint(rawKeyEncoded.byteArray), params)
        val publicKey =
            BCECPublicKey(KEY_GEN_ALGORITHM, keySpec, BouncyCastleProvider.CONFIGURATION)
        return publicKey
    }

    // this is from x509
    private fun x509toJavaPublicKey(byteArray: ByteArray): BCECPublicKey {
        // maybe add 04 byte in from to get DER encoding
        val bpubKey = PublicKeyFactory.createKey(byteArray) as ECPublicKeyParameters
        val kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM, "BC")
        val spec = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        return kf.generatePublic(ECPublicKeySpec(bpubKey.q, spec)) as BCECPublicKey
    }
}

fun JavaPublicKey.getBytes(): Bytes {
    val W = (this as BCECPublicKey).q
    val WX = W.affineXCoord
    val WY = W.affineYCoord
    // sometimes 1 biginteger is 31 bytes long
    val xBytes = WX.toBigInteger().toBytes(32)
    val yBytes = WY.toBigInteger().toBytes(32)
    val bytes = xBytes.concat(yBytes)
    return bytes
}

fun JavaPublicKey.getParameters(): ECPublicKeyParameters {
    return ECUtil.generatePublicKeyParameter(this) as ECPublicKeyParameters
}
