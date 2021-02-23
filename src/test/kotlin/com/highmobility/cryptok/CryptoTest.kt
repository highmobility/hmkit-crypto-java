package com.highmobility.cryptok

import com.highmobility.cryptok.value.PrivateKey
import com.highmobility.cryptok.value.PublicKey
import com.highmobility.cryptok.value.Signature
import com.highmobility.hmkit.HMKit
import com.highmobility.value.Bytes
import org.junit.Test

typealias CorePublicKey = com.highmobility.crypto.value.PublicKey
typealias CorePrivateKey = com.highmobility.crypto.value.PrivateKey

internal class CryptoTest {
    val cryptoK = Crypto()
    val cryptoCore = HMKit.getInstance().crypto

    @Test
    fun createKeypair() {
        val keypair = cryptoK.createKeypair()

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
        val serial = cryptoK.createSerialNumber()
        assert(serial.size == 9)
    }

    @Test
    fun signAndVerify() {
        val lessThan64BytesMessage = Bytes("AABB")

        // sign with a generated key. verify with the same generated key
        val keyPair = cryptoK.createKeypair()

        val sig = cryptoK.sign(lessThan64BytesMessage, keyPair.privateKey)
        assert(sig.size == 64)
        assert(cryptoK.verify(lessThan64BytesMessage, sig, keyPair.publicKey))
        assert(cryptoCore.verify(lessThan64BytesMessage, sig, CorePublicKey(keyPair.publicKey)))

        // verify the blocking until 64 method
        val moreThan64BytesMessage = Bytes(ByteArray(79))
        val sig2 = cryptoK.sign(moreThan64BytesMessage, keyPair.privateKey)
        assert(sig.size == 64)
        assert(cryptoK.verify(moreThan64BytesMessage, sig2, keyPair.publicKey))
        assert(cryptoCore.verify(moreThan64BytesMessage, sig2, CorePublicKey(keyPair.publicKey)))
    }

    @Test
    fun javaKeysWithCore() {
        val message = Bytes("AABB")
        val kKeyPair = cryptoK.createKeypair()

        val corePublic = CorePublicKey(kKeyPair.publicKey)
        val corePrivate = CorePrivateKey(kKeyPair.privateKey)

        // test the keys from java crypto: generate sig with private and verify with public
        val coreSig = cryptoCore.sign(message, corePrivate)
        assert(cryptoCore.verify(message, coreSig, corePublic))
        assert(cryptoK.verify(message, Signature(coreSig), kKeyPair.publicKey))

        val kSig = cryptoK.sign(message, kKeyPair.privateKey)
        assert(cryptoK.verify(message, kSig, kKeyPair.publicKey))
        assert(cryptoCore.verify(message, kSig, corePublic))
    }

    @Test
    fun testCoreKeysWithJava() {
        val message = Bytes("AABB")
        val coreKeyPair = cryptoCore.createKeypair()

        val public = PublicKey(coreKeyPair.publicKey)
        val private = PrivateKey(coreKeyPair.privateKey)

        // this means creating java keys with core bytes is correct
        val kSig = cryptoK.sign(message, private)
        assert(cryptoK.verify(message, kSig, public))
        // this means sign method is correct
        assert(cryptoCore.verify(message, kSig, coreKeyPair.publicKey))
    }

    @Test
    fun sha256() {
        val sha1 = cryptoK.sha256(Bytes("AAB1"))
        val sha2 = cryptoK.sha256(Bytes("AAB1"))
        val shaDifferent = cryptoK.sha256(Bytes("AAB2"))

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

        val shared = cryptoK.createSharedSecret(privateKey, publicKey)
        assert(shared == Bytes("17164A21309671D54484C3E6C3A3FF22E3F008E142E2A78B55124823F50AD77B"))
    }

    @Test
    fun hmac() {
        val message = Bytes("AABB")
        // shared key from DH ^^ method
        val shared = Bytes("17164A21309671D54484C3E6C3A3FF22E3F008E142E2A78B55124823F50AD77B")
        val expectedResult =
            Bytes("3573DF5D8EE68A67EFEEFE1544A0F90D46C204134FAD44EC14C7BCE3EA6DC736")
        val hmac = cryptoK.hmac(shared, message)
        assert(hmac == expectedResult)
    }

    @Test
    fun signJWT() {
        val private = cryptoK.createKeypair().privateKey
        val signature = cryptoK.signJWT("asd".toByteArray(), private)
        assert(signature.size == 64)
        // // TODO: 19/2/21 verify with fleet
    }

    @Test
    fun encrypt() {
    }

    @Test
    fun decrypt() {

    }

    @Test
    fun jwt() {
        val privateKey =
            PrivateKey("7FEE7D0CBBADFD4BF99AA8CECFF7036A0D767CACC6AA27BD5AB9E400805BC184")
        val message = Bytes("AABB")
        cryptoK.signJWT(message.byteArray, privateKey)
        // cannot test the signature, it is different every time
    }
}