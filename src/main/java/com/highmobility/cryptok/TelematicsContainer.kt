package com.highmobility.cryptok

import com.highmobility.cryptok.value.DeviceSerial
import com.highmobility.cryptok.value.PrivateKey
import com.highmobility.cryptok.value.PublicKey
import com.highmobility.value.Bytes
import java.util.ArrayList

/**
 * Contains the full telematics container bytes and ivars. Bytes are unescaped.
 */
class TelematicsContainer : Bytes {
    val crypto: Crypto

    // container fields, in order
    val senderSerialNumber: DeviceSerial
    val targetSerialNumber: DeviceSerial
    val nonce: Bytes
    val requestId: Bytes
    val encrypted: Boolean
    val contentType: Int

    // Command(payload) is encrypted with HM custom aes
    val payload: Bytes
    val hmac: Bytes

    // helper variables
    val senderPrivateKey: PrivateKey
    val targetPublicKey: PublicKey
    val sessionKey: Bytes

    /**
     *  Create the telematics container bytes from properties
     */
    constructor(
        crypto: Crypto,
        command: Bytes,
        senderPrivateKey: PrivateKey,
        targetPublicKey: PublicKey,
        senderSerialNumber: DeviceSerial,
        targetSerialNumber: DeviceSerial,
        nonce: Bytes,
        requestId: Bytes = Bytes(),
        encrypted: Boolean = true,
        contentType: Int = 1

    ) {
        this.crypto = crypto
        this.senderPrivateKey = senderPrivateKey
        this.targetPublicKey = targetPublicKey
        this.senderSerialNumber = senderSerialNumber
        this.targetSerialNumber = targetSerialNumber
        this.nonce = nonce
        this.requestId = requestId
        this.encrypted = encrypted
        this.contentType = contentType

        this.payload = createPayload(
            command, senderPrivateKey, targetPublicKey, nonce
        )

        val bytes = Bytes(30 + requestId.size + 2 + 4 + payload.size)
        bytes.set(0, 0x02)
        bytes.set(1, senderSerialNumber)
        bytes.set(10, targetSerialNumber)
        bytes.set(19, nonce)
        // request id is 0 bytes
        bytes.set(28, requestId.size.toBytes(2))
        bytes.set(30, requestId)
        var position = 30 + requestId.size
        bytes.set(position, encrypted.toByte())
        position += 1
        bytes.set(position, contentType.toByte())
        position += 1
        bytes.set(position, payload.size.toBytes(4))
        position += 4
        bytes.set(position, payload)

        // add hmac from the previous bytes
        this.sessionKey = crypto.createSessionKey(senderPrivateKey, targetPublicKey, nonce)
        this.hmac = crypto.hmac(sessionKey, bytes)

        val completeBytes = bytes.concat(hmac)
        this.bytes = completeBytes.byteArray
    }

    constructor(
        crypto: Crypto,
        escapedBytes: Bytes,
        senderPrivateKey: PrivateKey,
        targetPublicKey: PublicKey,
    ) {
        this.bytes = escapedBytes.unescapeAndRemoveStartEndBytes().byteArray
        this.crypto = crypto
        this.senderPrivateKey = senderPrivateKey
        this.targetPublicKey = targetPublicKey

        if (bytes.size < 36 + 32) throw IllegalArgumentException("Container too small")
        if (bytes[0] != 0x02.toByte()) throw IllegalArgumentException("Only v2 is supported")

        var position = 1
        this.senderSerialNumber = DeviceSerial(getRange(position, position + 9))
        position += 9
        this.targetSerialNumber = DeviceSerial(getRange(position, position + 9))
        position += 9
        this.nonce = Bytes(getRange(position, position + 9))
        position += 9

        val requestIdSize = getRange(position, position + 2).toInt()
        position += 2

        this.requestId = getRange(position, position + requestIdSize)
        position += requestIdSize

        this.encrypted = bytes[position].toBoolean()
        position += 1

        this.contentType = bytes[position].toInt()
        position += 1

        val payLoadSize = getRange(position, position + 4).toInt()
        position += 4

        this.payload = getRange(position, position + payLoadSize)
        position += payLoadSize

        // verify hmac
        hmac = getRange(position, position + 32)

        this.sessionKey = crypto.createSessionKey(senderPrivateKey, targetPublicKey, nonce)
        val verifyHmac = crypto.hmac(sessionKey, getRange(0, size - 32))
        if (verifyHmac != hmac) throw IllegalArgumentException("Invalid HMAC")
    }

    /**
     * The unencrypted raw command in the payload portion
     *
     * @return The unenncrypted command
     */
    fun getUnencryptedPayload(): Bytes {
        return if (encrypted) {
            val decrypted = crypto.encryptDecrypt(payload, senderPrivateKey, targetPublicKey, nonce)
            decrypted.getRange(0, decrypted.size)
        } else {
            this.payload
        }
    }

    fun getEscapedAndWithStartEndBytes(): Bytes {
        return this.escapeAndAddStartEndBytes()
    }

    /**
     * Message will be encrypted by HM custom AES (create a secure command
     * container: https://highmobility.atlassian.net/wiki/spaces/HC/pages/551321631/Telematics+Container+pseudocodes)
     *
     * @return The Telematics command payload part
     */
    private fun createPayload(
        message: Bytes,
        senderPrivateKey: PrivateKey,
        targetPublicKey: PublicKey,
        nonce: Bytes
    ): Bytes {
        return crypto.encryptDecrypt(
            message,
            senderPrivateKey,
            targetPublicKey,
            nonce
        )
    }

    /**
     * escape the 0x00 bytes and add start/end byte
     * @return The escaped bytes
     */
    private fun Bytes.escapeAndAddStartEndBytes(): Bytes {
        val result = ArrayList<Byte>()

        result.add(0x00)

        for (i in 0 until this.size) {
            if (this[i] == 0x00.toByte() ||
                this[i] == 0xfe.toByte() ||
                this[i] == 0xff.toByte()
            ) {
                result.add(0xFE.toByte())
            }

            result.add(this[i])
        }

        result.add(0xFF.toByte())

        return Bytes(result.toByteArray())
    }

    /**
     * Unescape the 0x00 bytes and add start/end byte
     *
     * @return The escaped bytes
     */
    private fun Bytes.unescapeAndRemoveStartEndBytes(): Bytes {
        if (this[0] != 0x00.toByte()) {
            throw IllegalArgumentException("Invalid start byte")
        }

        if (this[this.size - 1] != 0xFF.toByte()) {
            throw IllegalArgumentException("Invalid end byte")
        }

        val result = ArrayList<Byte>()
        var i = 1
        while (i < this.size - 1) {
            if (this[i] == 0xFE.toByte()) {
                i++
                result.add(this[i])
            } else {
                result.add(this[i])
            }
            i++
        }

        return Bytes(result.toByteArray())
    }
}