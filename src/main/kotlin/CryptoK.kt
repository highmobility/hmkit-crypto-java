import com.highmobility.crypto.HMKeyPair
import com.highmobility.crypto.value.*
import com.highmobility.crypto.value.PrivateKey
import com.highmobility.crypto.value.PublicKey
import com.highmobility.crypto.value.Signature

import com.highmobility.utils.Base64
import com.highmobility.value.Bytes
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import java.security.interfaces.ECPrivateKey
//import java.security.Signature

import java.util.*

import org.bouncycastle.asn1.sec.SECNamedCurves

import org.bouncycastle.crypto.params.ECPrivateKeyParameters

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters

import org.bouncycastle.crypto.signers.HMacDSAKCalculator

import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec

import java.security.*
import java.security.KeyFactory

import java.security.spec.PKCS8EncodedKeySpec


typealias JavaSignature = java.security.Signature
typealias JavaPrivateKey = java.security.PrivateKey
typealias JavaPublicKey = java.security.PublicKey

/*
Platform: key-pair generation
Key-pair used in Public-Key Infrastructure
ECDH secp256r1


Platform: Device certificate signature
Signature for downloading access certificates
ECDSA, SHA256


Platform: JWT signature
For signing Service Account API requests
ES256
 */
// secp256r1, prime256v1

val CURVE_NAME = "secp256r1"
val params = SECNamedCurves.getByName(CURVE_NAME);
val CURVE = ECDomainParameters(params.curve, params.g, params.n, params.h);

class CryptoK {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    /**
     * Create a keypair.
     *
     * @return The KeyPair.
     */
    fun createKeypair(): HMKeyPair {
        val javaKeyPair = generateJavaKeyPair()
        val javaPublicKey = javaKeyPair.public
        val publicKey = PublicKey(javaKeyPair.public.getBytes())
        val privateKey = PrivateKey(javaKeyPair.private.getBytes())

        return HMKeyPair(privateKey, publicKey)
    }

    /**
     * Create a random serial number.
     *
     * @return the serial number.
     */
    fun createSerialNumber(): DeviceSerial? {
        val serialBytes = ByteArray(9)
        Random().nextBytes(serialBytes)
        return DeviceSerial(serialBytes)
    }

    /**
     * Sign data.
     *
     * @param bytes      The data that will be signed.
     * @param privateKey The private key that will be used for signing.
     * @return The signature.
     */
    fun sign(bytes: Bytes, privateKey: PrivateKey): Signature {
        return sign(bytes.byteArray, privateKey)
    }

    /**
     * Sign data.
     *
     * @param bytes      The data that will be signed.
     * @param privateKey The private key that will be used for signing.
     * @return The signature.
     */
    fun sign(bytes: ByteArray, privateKey: PrivateKey): Signature {
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        val javaPrivateKey = privateKey.toJavaKey()
        val privKeyParams = ECPrivateKeyParameters(javaPrivateKey.d, CURVE)
        signer.init(true, privKeyParams)

        val components = signer.generateSignature(bytes)
        val bytes = components[0].toBytes(32)
            .concat(components[1].toBytes(32))
        return Signature(bytes)
    }

    /**
     * Verify a signature.
     *
     * @param data      The data that was signed.
     * @param signature The signature.
     * @param publicKey The public key that is used for verifying.
     * @return The verification result.
     */
    fun verify(data: Bytes, signature: Signature, publicKey: PublicKey): Boolean {
        val signer = ECDSASigner()
        val javaPublicKey = publicKey.toJavaKey()
        val params = ECPublicKeyParameters(
            CURVE.curve.decodePoint(javaPublicKey.encoded), CURVE
        );
        signer.init(false, params)

        val sigComponents = signature.components()
        return signer.verifySignature(data.byteArray, sigComponents[0], sigComponents[1]);
    }

    /**
     * Verify a signature.
     *
     * @param data      The data that was signed.
     * @param signature The signature.
     * @param publicKey The public key that is used for verifying.
     * @return The verification result.
     */
    fun verify(data: Bytes, signature: Signature, publicKey: ByteArray): Boolean {
        return verify(data, signature, publicKey)
        // TODO: 9/2/21 verify this is needed
    }

    fun signJWT(bytes: ByteArray, privateKey: PrivateKey): Signature {
        val signature = ByteArray(64)
//        core.HMBTCoreCryptoJWTAddSignature(
//            bytes, bytes.size,
//            privateKey.byteArray, signature
//        )
        return Signature(signature)
    }

    fun signJWT(bytes: Bytes, privateKey: PrivateKey): Signature {
        return signJWT(bytes.byteArray, privateKey)
    }

    fun sha256(bytes: ByteArray): Sha256? {
        val sha256 = ByteArray(32)
//        core.HMBTCoreCryptoJWTsha(bytes, bytes.size, sha256)
        return sha256(sha256)
    }

    fun sha256(bytes: Bytes): Sha256? {
        return sha256(bytes.byteArray)
    }

    // TODO: these should probably go to separate class/fleet module

    fun encrypt() {

    }

    fun decrypt() {

    }

    fun decodeKey(encoded: ByteArray?): BCECPublicKey? {
        val params = ECNamedCurveTable.getParameterSpec("secp256r1")
        val keySpec = ECPublicKeySpec(params.curve.decodePoint(encoded), params)
        return BCECPublicKey("ECDSA", keySpec, BouncyCastleProvider.CONFIGURATION)
    }

    private fun getServiceAccountHmPrivateKey(serviceAccountApiPrivateKey: String): PrivateKey {
        val bigIntegerBytes =
            getServiceAccountJavaPrivateKey(serviceAccountApiPrivateKey).s.toByteArray()
        val privateKeyBytes = ByteArray(32)

        for (i in 0..31) {
            privateKeyBytes[i] = bigIntegerBytes[i + 1]
        }

        return PrivateKey(privateKeyBytes)
    }

    /**
     * This private key is downloaded when creating a Service Account API key. It should be in
     * PKCS 8 format
     */
    private fun getServiceAccountJavaPrivateKey(serviceAccountApiPrivateKey: String): ECPrivateKey {
        var encodedKeyString = serviceAccountApiPrivateKey
        encodedKeyString = encodedKeyString.replace("-----BEGIN PRIVATE KEY----", "")
        encodedKeyString = encodedKeyString.replace("-----END PRIVATE KEY-----", "")
        val decodedPrivateKey = Base64.decode(encodedKeyString)
        val keySpec = PKCS8EncodedKeySpec(decodedPrivateKey)
        // how to convert PKCS#8 to EC private key https://stackoverflow.com/a/52301461/599743
        val kf = KeyFactory.getInstance("EC", "BC")
        val ecPrivateKey = kf.generatePrivate(keySpec) as ECPrivateKey
        return ecPrivateKey
    }

    /**
     * This key is paired with the app's client certificate. It should be the 32 bytes of the
     * ANSI X9.62 Prime 256v1 curve in hex or base64.
     */
    private fun getClientPrivateKey(clientPrivateKey: String): PrivateKey {
        return PrivateKey(clientPrivateKey)
    }

    private fun BigInteger.toBytes(): Bytes {
        var data = this.toByteArray()
        if (data.size != 1 && data[0] == 0.toByte()) {
            val tmp = ByteArray(data.size - 1)
            System.arraycopy(data, 1, tmp, 0, tmp.size)
            data = tmp
        }
        return Bytes(data)
    }

    private fun BigInteger.toBytes(numBytes: Int): Bytes {
        val bytes = ByteArray(numBytes)
        val biBytes = this.toByteArray()
        val start = if (biBytes.size == numBytes + 1) 1 else 0
        val length = Math.min(biBytes.size, numBytes)
        System.arraycopy(biBytes, start, bytes, numBytes - length, length)
        return Bytes(bytes)
    }

    private fun JavaPrivateKey.getBytes(): Bytes? {
        return if (this == null) {
            null
        } else if (this is BCECPrivateKey) {
            this.d.toBytes(32)
        } else {
            null
        }
    }


    private fun generateJavaKeyPair(): KeyPair {
        val ecSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("P-256")
        val g = KeyPairGenerator.getInstance("ECDSA", "BC")
        g.initialize(ecSpec, SecureRandom())
        return g.generateKeyPair()
    }

    /**
     * Returns the signature r and s components
     */
    private fun Signature.components(): Array<BigInteger> {
        val r = getRange(0, 32)
        val s = getRange(32, 64)
        return arrayOf(BigInteger(1, r.byteArray), BigInteger(1, s.byteArray))
    }
}