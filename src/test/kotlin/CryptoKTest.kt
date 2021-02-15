import com.highmobility.crypto.value.PrivateKey
import com.highmobility.crypto.value.PublicKey
import com.highmobility.value.Bytes
import org.junit.Test

internal class CryptoKTest {
    val cryptoK = CryptoK()
    val msg = Bytes("AABB")
    // TODO: 15/2/21 remove 0..1000 it is in because sometimes some points were 63byte instead of 64

    @Test
    fun createKeypair() {
        for (i in 0..1000) {
            val keypair = cryptoK.createKeyPair()

            assert(keypair.privateKey.size == 32)
            assert(keypair.publicKey.size == 64)

            keypair.publicKey.toJavaKey()
            keypair.privateKey.toJavaKey()
        }
    }

    @Test
    fun publicToJavaAndBack() {
        for (i in 0..1000) {
            // convert key to java and back and see if the bytes are the same
            val publicKey =
                PublicKey("E759E9D7594504EA36180549F5276B12396B2EE9B8B37C5E452B78CE29D95A97D6A3EC2BDA924FAE15BED2D6FBC263FFB4CBECF27F6BA6CA066DE660DA19D97B")

            val javaKey = publicKey.toJavaKey()
            val fromJava = PublicKey(javaKey)
            assert(publicKey == fromJava)
        }
    }

    @Test
    fun privateToJavaAndBack() {
        for (i in 0..1000) {
            val privateKey =
                PrivateKey("7FEE7D0CBBADFD4BF99AA8CECFF7036A0D767CACC6AA27BD5AB9E400805BC184")

            val javaKey = privateKey.toJavaKey()
            val fromJava = PrivateKey(javaKey)
            assert(privateKey == fromJava)
        }
    }

    @Test
    fun createSerialNumber() {
        val serial = cryptoK.createSerialNumber()
        assert(serial.size == 9)
    }

    @Test
    fun signAndVerifyWithJavaKeys() {
        for (i in 0..1000) {
            // sign with a generated key and verify with the same generated key
            val keyPair = cryptoK.createJavaKeyPair()

            val sig = cryptoK.sign(msg.byteArray, keyPair.private)
            val verifyResult = cryptoK.verify(msg.byteArray, sig, keyPair.public)
            assert(verifyResult)
        }
    }

    @Test
    fun signAndVerify() {
        // sign with a generated key. verify with the same generated key
        val keyPair = cryptoK.createKeyPair()

        val sig = cryptoK.sign(msg, keyPair.privateKey)
        assert(sig.size == 64)
        assert(cryptoK.verify(msg, sig, keyPair.publicKey))
    }

    @Test
    fun signAndVerifyWithKeysFromHmCryptoTool() {
//        val privateKey =
//            PrivateKey("7FEE7D0CBBADFD4BF99AA8CECFF7036A0D767CACC6AA27BD5AB9E400805BC184")
//        val publicKey =
//            PublicKey("E759E9D7594504EA36180549F5276B12396B2EE9B8B37C5E452B78CE29D95A97D6A3EC2BDA924FAE15BED2D6FBC263FFB4CBECF27F6BA6CA066DE660DA19D97B")
//
//        val sig = cryptoK.sign(msg, privateKey)
//        assert(sig.size == 64)
//
//        assert(cryptoK.verify(msg, sig, publicKey))
    }

    @Test
    fun testKeysWithHMCrypto() {
        // generate a keypair
        // get hex from it
        // sign/verify with hmcrypto tool

        // generate hmcrypto keys
        // sign/verify with those
    }

    @Test
    fun signJWT() {
    }

    @Test
    fun sha256() {
    }

    @Test
    fun encrypt() {
    }

    @Test
    fun decrypt() {

    }

    @Test
    fun jwt() {
    }
}