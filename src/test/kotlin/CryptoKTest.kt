import com.highmobility.crypto.value.PrivateKey
import com.highmobility.crypto.value.PublicKey
import com.highmobility.value.Bytes
import org.junit.Test

internal class CryptoKTest {
    val cryptoK = CryptoK()
    val msg = Bytes("AABB")

    @Test
    fun createKeypair() {
        val keypair = cryptoK.createKeypair()

        assert(keypair.privateKey.size == 32)
        assert(keypair.publicKey.size == 64)
    }

    @Test
    fun createSerialNumber() {

    }

    @Test
    fun signAndVerify() {
        // test: sign with a generated key. verify with the same generated key
        val keyPair = cryptoK.createKeypair()

        val sig = cryptoK.sign(msg, keyPair.privateKey)
        assert(sig.size == 64)

        assert(cryptoK.verify(msg, sig, keyPair.publicKey))
    }

    @Test
    fun publicToJavaAndBack() {
        // convert key to java and back and see if the bytes are the same
        val publicKey =
            PublicKey("E759E9D7594504EA36180549F5276B12396B2EE9B8B37C5E452B78CE29D95A97D6A3EC2BDA924FAE15BED2D6FBC263FFB4CBECF27F6BA6CA066DE660DA19D97B")

        val javaKey = publicKey.toJavaKey()
        val fromJava = PublicKey(javaKey)
        assert(publicKey == fromJava)
    }

    @Test
    fun privateToJavaAndBack() {
        val publicKey =
            PublicKey("7FEE7D0CBBADFD4BF99AA8CECFF7036A0D767CACC6AA27BD5AB9E400805BC184")

        // TODO: 9/2/21 just convert to java and back and see if the bytes are the same
    }

    @Test
    fun signAndVerifyWithKeysFromHmCryptoTool() {
        val privateKey =
            PrivateKey("7FEE7D0CBBADFD4BF99AA8CECFF7036A0D767CACC6AA27BD5AB9E400805BC184")
        val publicKey =
            PublicKey("E759E9D7594504EA36180549F5276B12396B2EE9B8B37C5E452B78CE29D95A97D6A3EC2BDA924FAE15BED2D6FBC263FFB4CBECF27F6BA6CA066DE660DA19D97B")

        val sig = cryptoK.sign(msg, privateKey)
        assert(sig.size == 64)

        assert(cryptoK.verify(msg, sig, publicKey))
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