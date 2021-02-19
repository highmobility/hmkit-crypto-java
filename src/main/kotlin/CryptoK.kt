import com.highmobility.cryptok.HMKeyPair
import com.highmobility.cryptok.value.*
import com.highmobility.cryptok.value.PrivateKey
import com.highmobility.cryptok.value.PublicKey
import com.highmobility.cryptok.value.Signature
import com.highmobility.value.Bytes
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import java.security.*
import java.util.*

typealias JavaSignature = java.security.Signature
typealias JavaPrivateKey = java.security.PrivateKey
typealias JavaPublicKey = java.security.PublicKey

/*
Key-pair used in Public-Key Infrastructure: ECDH secp256r1
Signature for downloading access certificates: ECDSA, SHA256
JWT signature For signing Service Account API requests: ES256
 */

val KEY_GEN_ALGORITHM = "EC" // ECDH and ECDSA can be used with same algorithm
var SIGN_ALGORITHM = "SHA256withPLAIN-ECDSA"

val CURVE_NAME = "secp256r1" // this is 1.3.132.0.prime256v1
val params = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
val CURVE = ECDomainParameters(params.curve, params.g, params.n, params.h)
val CURVE_SPEC = ECParameterSpec(params.curve, params.g, params.n, params.h)

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
    fun createKeypair(): HMKeyPair {
        val javaKeyPair = createJavaKeypair()
        val publicKeyBytes = javaKeyPair.public.getBytes()

        val publicKey = PublicKey(publicKeyBytes)
        val privateKey = PrivateKey(javaKeyPair.private.getBytes())

        return HMKeyPair(privateKey, publicKey)
    }

    fun createJavaKeypair(): KeyPair {
        val ecSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME)
        val g = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM, "BC")
        g.initialize(ecSpec, SecureRandom())
        val javaKeyPair = g.generateKeyPair()
        return javaKeyPair
    }

    fun verify(message: Bytes, signature: Signature, publicKey: JavaPublicKey): Boolean {
        val formattedMessage = message.fillWith0sUntil64()

        val ecdsaVerify = JavaSignature.getInstance("SHA256withPLAIN-ECDSA", "BC")
        ecdsaVerify.initVerify(publicKey)
        ecdsaVerify.update(formattedMessage.byteArray)
        val result = ecdsaVerify.verify(signature.byteArray)
        return result
    }

    /**
     * Sign data.
     *
     * @param message      The message that will be signed.
     * @param privateKey The private key that will be used for signing.
     * @return The signature.
     */
    fun sign(message: Bytes, privateKey: PrivateKey): Signature {
        val formattedMessage = message.fillWith0sUntil64()
        // https://stackoverflow.com/questions/34063694/fixed-length-64-bytes-ec-p-256-signature-with-jce
        // there are also withCVC-ECDSA, withECDSA
        val signature = JavaSignature.getInstance(SIGN_ALGORITHM, "BC")
        signature.initSign(privateKey.toJavaKey())
        signature.update(formattedMessage.byteArray)
        val sigBytes = signature.sign()
        return Signature(sigBytes)
    }

    /**
     * Sign data.
     *
     * @param message      The message that will be signed.
     * @param privateKey The private key that will be used for signing.
     * @return The signature.
     */
    fun sign(message: ByteArray, privateKey: PrivateKey): Signature {
        return sign(Bytes(message), privateKey)
    }

    /**
     * Verify a signature.
     *
     * @param message      The message that was signed.
     * @param signature The signature.
     * @param publicKey The public key that is used for verifying.
     * @return The verification result.
     */
    fun verify(message: Bytes, signature: Signature, publicKey: PublicKey): Boolean {
        return verify(message, signature, publicKey.toJavaKey())
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

    fun sha256(bytes: ByteArray): Sha256 {
        val digest = MessageDigest.getInstance("SHA-256", "BC")
        return Sha256(digest.digest(bytes))
    }

    fun sha256(bytes: Bytes): Sha256 {
        return sha256(bytes.byteArray)
    }

    /**
     * Create JWT signature. It is the same as normal signing, but without padding to 64
     *
     * @param message The message
     * @param privateKey The private key
     * @return The signature
     */
    fun signJWT(message: ByteArray, privateKey: PrivateKey): Signature {
        val signature = JavaSignature.getInstance(SIGN_ALGORITHM, "BC")
        signature.initSign(privateKey.toJavaKey())
        signature.update(message)
        val sigBytes = signature.sign()
        return Signature(sigBytes)
    }

    /**
     * Create JWT signature. It is the same as normal signing, but without padding to 64
     *
     * @param message The message
     * @param privateKey The private key
     * @return The signature
     */
    fun signJWT(message: Bytes, privateKey: PrivateKey): Signature {
        return signJWT(message.byteArray, privateKey)
    }

    // TODO: these could go to separate class or to fleet module
    fun encrypt(message: Bytes, privateKey: PrivateKey, publicKey: PublicKey) {

    }

    fun decrypt() {

    }

    private fun encryptDecrypt() {

    }
}