//import java.security.Signature

import com.highmobility.crypto.HMKeyPair
import com.highmobility.crypto.value.*
import com.highmobility.utils.Base64
import com.highmobility.value.Bytes
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

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
val CURVE_SPEC = ECParameterSpec(params.curve, params.g, params.n, params.h);

class CryptoK {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    /**
     * Create a random serial number.
     *
     * @return the serial number.
     */
    fun createSerialNumber(): DeviceSerial {
        val serialBytes = ByteArray(9)
        Random().nextBytes(serialBytes)
        return DeviceSerial(serialBytes)
    }

    /**
     * Create a keypair.
     *
     * @return The KeyPair.
     */
    fun createKeyPair(): HMKeyPair {
        val javaKeyPair = createJavaKeyPair()
        val publicKeyBytes = javaKeyPair.public.getBytes()

        val publicKey = PublicKey(publicKeyBytes)
        val privateKey = PrivateKey(javaKeyPair.private.getBytes())

        return HMKeyPair(privateKey, publicKey)
    }

    fun createJavaKeyPair(): KeyPair {
        val ecSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        val g = KeyPairGenerator.getInstance("ECDSA", "BC")
        g.initialize(ecSpec, SecureRandom())
        val javaKeyPair = g.generateKeyPair()
        return javaKeyPair
    }

    fun sign(bytes: ByteArray, privateKey: JavaPrivateKey): Signature {
        // https://stackoverflow.com/questions/48783809/ecdsa-sign-with-bouncycastle-and-verify-with-crypto
        // there are also withCVC-ECDSA, withECDSA
        val signature = JavaSignature.getInstance("SHA256withPLAIN-ECDSA", "BC")
        signature.initSign(privateKey)

        signature.update(bytes)
        val sigBytes: ByteArray = signature.sign()
        return Signature(sigBytes)
    }

    fun verify(data: ByteArray, signature: Signature, publicKey: JavaPublicKey): Boolean {
        val ecdsaVerify = JavaSignature.getInstance("SHA256withPLAIN-ECDSA", "BC")
        ecdsaVerify.initVerify(publicKey)
        ecdsaVerify.update(data)
        val result: Boolean = ecdsaVerify.verify(signature.byteArray)
        return result
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
        return sign(bytes, privateKey.toJavaKey())
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
        return verify(data.byteArray, signature, publicKey.toJavaKey())
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
        return verify(data, signature, PublicKey(publicKey))
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
}