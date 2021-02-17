import com.highmobility.crypto.value.PublicKey
import com.highmobility.crypto.value.SignatureK
import com.highmobility.hmkit.HMKit
import com.highmobility.value.Bytes
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.util.*
import kotlin.experimental.and

class SignTest {
    val coreCrypto = HMKit.getInstance().crypto

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun createJavaKeypair(): KeyPair {
        // a key generated as EC can be used with either ECDH or ECDSA. https://security.stackexchange.com/a/190881
        val g = KeyPairGenerator.getInstance("EC", "BC")
        g.initialize(ECNamedCurveTable.getParameterSpec("secp256r1"))
        return g.generateKeyPair()
    }

    fun KeyPair.getPublicKeyBytes(): PublicKey {
        // core code https://github.com/highmobility/hmkit-crypto-c/blob/187b31dfdd6f072c36a519d1e0138ab6b744223b/Crypto.c#L372-L372
        val W = (public as BCECPublicKey).q
        val WX = W.affineXCoord
        val WY = W.affineYCoord

        // sometimes 1 biginteger is 31 bytes long, then we prepend 0
        val xBytes = WX.toBigInteger().toBytes(32)
        val yBytes = WY.toBigInteger().toBytes(32)
        val bytes = xBytes.concat(yBytes)

        // PublicKey is just the raw bytes container
        return PublicKey(bytes)
    }

    // use java keys to create the signature, then verify with openSSL
    @Test
    fun testSignAndVerifyWithCore() {
        val message = Bytes("AABB")
        val kKeyPair = createJavaKeypair()
        val kPrivate = kKeyPair.private

        val kSig1 = sign1(message, kPrivate)
        val verify1 = coreCrypto.verify(message, kSig1, kKeyPair.getPublicKeyBytes())
        println("verify1 $verify1")

        val kSig2 = sign2(message, kPrivate)
        val verify2 = coreCrypto.verify(message, kSig2, kKeyPair.getPublicKeyBytes())
        println("verify2 $verify2")
    }

    fun sign1(message: Bytes, privateKey: JavaPrivateKey): SignatureK {
        val signature = JavaSignature.getInstance("SHA256withECDSA", "BC")
        signature.initSign(privateKey)
        signature.update(message.byteArray)
        val derSig = signature.sign()
        // der format: 0x30 0x44 0x02 0x20 (vr) 0x02 0x20 (vs)
        val r = extractR(derSig).toBytes(32).byteArray
        val s = extractS(derSig).toBytes(32).byteArray

        return SignatureK(r + s)
    }

    fun sign2(bytes: Bytes, privateKey: JavaPrivateKey): SignatureK {
        // https://stackoverflow.com/questions/34063694/fixed-length-64-bytes-ec-p-256-signature-with-jce
        // there are also withCVC-ECDSA, withECDSA
        val signature = JavaSignature.getInstance("SHA256withPLAIN-ECDSA", "BC")
        signature.initSign(privateKey)
        signature.update(bytes.byteArray)
        val sigBytes = signature.sign()
        return SignatureK(sigBytes)
    }

    fun extractR(signature: ByteArray): BigInteger {
        val startR = if (signature[1].and(0x80.toByte()) != 0.toByte()) 3 else 2
        val lengthR = signature[startR + 1].toInt()
        return BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR))
    }

    fun extractS(signature: ByteArray): BigInteger {
        val startR = if (signature[1].and(0x80.toByte()) != 0.toByte()) 3 else 2
        val lengthR = signature[startR + 1].toInt()
        val startS = startR + 2 + lengthR
        val lengthS = signature[startS + 1].toInt()
        return BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS))
    }

    // prepend 00 if numBytes bigger. remove from beginning if numBytes smaller
    fun BigInteger.toBytes(numBytes: Int): Bytes {
        val bytes = ByteArray(numBytes)
        val biBytes = this.toByteArray()
        val start = if (biBytes.size == numBytes + 1) 1 else 0
        val length = Math.min(biBytes.size, numBytes)
        System.arraycopy(biBytes, start, bytes, numBytes - length, length)
        return Bytes(bytes)
    }

    // use core keys to create sig, then verify with core
    /*@Test
    fun testVerifyCoreSignature() {
        val message = Bytes("AABB")
        val coreKeyPair = coreCrypto.createKeypair()

        val corePublic = coreKeyPair.publicKey
        val corePrivate = coreKeyPair.privateKey

        val coreSig = coreCrypto.sign(message, corePrivate)
        // verify with core succeeds
        assert(coreCrypto.verify(message, coreSig, coreKeyPair.publicKey))

        assert(kCrypto.verify(message, SignatureK(coreSig), PublicKeyK(coreKeyPair.publicKey)))
    }*/
}