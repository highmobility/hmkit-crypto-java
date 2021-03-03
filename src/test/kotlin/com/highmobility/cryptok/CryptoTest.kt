package com.highmobility.cryptok

import com.highmobility.cryptok.value.PrivateKey
import com.highmobility.cryptok.value.PublicKey
import com.highmobility.value.Bytes
import org.junit.Test
import java.util.*

internal class CryptoTest {
    val crypto = Crypto()

    @Test
    fun createKeypair() {
        val keypair = crypto.createKeypair()

        assert(keypair.privateKey.size == 32)
        assert(keypair.publicKey.size == 64)

        keypair.publicKey.toJavaKey()
        keypair.privateKey.toJavaKey()
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
        val privateKey =
            PrivateKey("7FEE7D0CBBADFD4BF99AA8CECFF7036A0D767CACC6AA27BD5AB9E400805BC184")

        val javaKey = privateKey.toJavaKey()
        val fromJava = PrivateKey(javaKey)
        assert(privateKey == fromJava)
    }

    @Test
    fun createSerialNumber() {
        val serial = crypto.createSerialNumber()
        assert(serial.size == 9)
    }

    @Test
    fun signAndVerify() {
        val lessThan64BytesMessage = Bytes("AABB")

        // sign with a generated key. verify with the same generated key
        val keyPair = crypto.createKeypair()

        val sig = crypto.sign(lessThan64BytesMessage, keyPair.privateKey)
        assert(sig.size == 64)
        assert(crypto.verify(lessThan64BytesMessage, sig, keyPair.publicKey))

        // verify the blocking until 64 method
        val moreThan64BytesMessage = Bytes(ByteArray(79))
        val sig2 = crypto.sign(moreThan64BytesMessage, keyPair.privateKey)
        assert(sig.size == 64)
        assert(crypto.verify(moreThan64BytesMessage, sig2, keyPair.publicKey))
    }

    @Test
    fun sha256() {
        val sha1 = crypto.sha256(Bytes("AAB1"))
        val sha2 = crypto.sha256(Bytes("AAB1"))
        val shaDifferent = crypto.sha256(Bytes("AAB2"))

        assert(sha1.size == 32)
        assert(sha1 == sha2)
        assert(sha1 != shaDifferent)
    }

    @Test
    fun sharedKey() {
        val privateKey =
            PrivateKey("7FEE7D0CBBADFD4BF99AA8CECFF7036A0D767CACC6AA27BD5AB9E400805BC184")
        val publicKey =
            PublicKey("E759E9D7594504EA36180549F5276B12396B2EE9B8B37C5E452B78CE29D95A97D6A3EC2BDA924FAE15BED2D6FBC263FFB4CBECF27F6BA6CA066DE660DA19D97B")

        val shared = crypto.createSharedSecret(privateKey, publicKey)
        assert(shared == Bytes("17164A21309671D54484C3E6C3A3FF22E3F008E142E2A78B55124823F50AD77B"))
    }

    @Test
    fun hmac() {
        val message = Bytes("AABB")
        // shared key from DH ^^ method
        val shared = Bytes("17164A21309671D54484C3E6C3A3FF22E3F008E142E2A78B55124823F50AD77B")
        val expectedResult =
            Bytes("A8C42FB05152B4FD715CAAAD4C7AAFEE7F3FF17ED6CA77725411542640E953A1")
        val hmac = crypto.hmac(shared, message)
        assert(hmac == expectedResult)
    }

    @Test
    fun signJWT() {
        val private = crypto.createKeypair().privateKey
        val signature = crypto.signJWT("asd".toByteArray(), private)
        assert(signature.size == 64)
        // verified with backend
    }

    @Test
    fun computeSecret() {
        val alicePrivateKey =
            PrivateKey("F4915A98F534485DF9CB77384CEB757EB3706A665441C5120F976F38EBBBC69C")
        val bobPublicKey =
            PublicKey("B9E4DDEC5191947C019A39FC3EFC2E4322119E9425A60A5116244CCB9260F90B34DB78725314167D421EF79865F75C18471671447370F01130B2116E583B4286")
        val expectedSharedKey =
            Bytes("80F2B6AD92E8C0158AD5313E566D492596A7C20E36CB29D3DF0387F6E5F66AFF")
        assert(crypto.createSharedSecret(alicePrivateKey, bobPublicKey) == expectedSharedKey)
    }

    @Test
    fun encryptDecrypt() {
        // values are from node
        val bobPrivateKey =
            PrivateKey("F4915A98F534485DF9CB77384CEB757EB3706A665441C5120F976F38EBBBC69C")
        val alicePublicKey =
            PublicKey("9E99B4483DD47A42492D34BC9EEE5304A52672A0F08E895AA355201A7B5782CE61C5D6485EEEFBBA9F7A229C0A508C835568ED6A6670C9AAA4E8019D0C2F5201")
        val expectedEncrypted =
            Bytes("BCF57741E9DD8F53D2FA2E19EE7AAF315FB311C7A0E9542B2D251F6F0D7D45A46C92ECC9E5")
        val nonce = Bytes("000102030405060708")
        val message = Bytes("3601000100")
        val sessionKey = crypto.createSessionKey(bobPrivateKey, alicePublicKey, nonce)
        val messageWithHmac = message.concat(crypto.hmac(sessionKey, message))
        val encryptedMessage =
            crypto.encryptDecrypt(messageWithHmac, bobPrivateKey, alicePublicKey, nonce)

        assert(encryptedMessage == expectedEncrypted)

        val decryptedMessage =
            crypto.encryptDecrypt(encryptedMessage, bobPrivateKey, alicePublicKey, nonce)
        assert(decryptedMessage == messageWithHmac)
    }

    @Test
    fun encryptDecrypt1000TimesWithRandomValues() {
        var previousMessage = Bytes(byteArrayOf())
        var previousEncryptedMessage = Bytes(byteArrayOf())
        for (i in 0 until 1000) {
            val aliceKeys = crypto.createKeypair()
            val bobKeys = crypto.createKeypair()
            val randomSize = Math.floor(Math.random() * (1000 - 1) + 1)
            val message = Bytes(ByteArray(randomSize.toInt()))
            Random().nextBytes(message.byteArray)
            val nonce = crypto.createSerialNumber()
            val encryptedMessage = crypto.encryptDecrypt(
                Bytes(message),
                bobKeys.privateKey,
                aliceKeys.publicKey,
                nonce
            )
            val decryptedMessage = crypto.encryptDecrypt(
                encryptedMessage,
                aliceKeys.privateKey,
                bobKeys.publicKey,
                nonce
            )

            assert(decryptedMessage == message)
            assert(message != previousMessage)
            assert(encryptedMessage != previousEncryptedMessage)
            previousEncryptedMessage = encryptedMessage
            previousMessage = message
        }
    }
}