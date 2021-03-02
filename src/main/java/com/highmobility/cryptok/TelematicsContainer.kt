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

    val senderPrivateKey: PrivateKey
    val targetPublicKey: PublicKey
    val senderSerialNumber: DeviceSerial
    val targetSerialNumber: DeviceSerial
    val nonce: Bytes

    val requestId: Bytes
    val encryptedFlag: Int
    val contentType: Int

    // Command(payload) is contained in 0x36 container and encrypted with HM custom aes
    val payload: Bytes
    val hmac: Bytes

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
        encryptedFlag: Int = 1,
        contentType: Int = 1

    ) {
        this.crypto = crypto
        this.senderPrivateKey = senderPrivateKey
        this.targetPublicKey = targetPublicKey
        this.senderSerialNumber = senderSerialNumber
        this.targetSerialNumber = targetSerialNumber
        this.nonce = nonce
        this.requestId = requestId
        this.encryptedFlag = encryptedFlag
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
        bytes.set(position, 1)
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
        this.bytes = completeBytes.escapeAndAddStartEndBytes().byteArray
    }

    constructor(
        crypto: Crypto,
        escapedBytes: Bytes,
        senderPrivateKey: PrivateKey,
        targetPublicKey: PublicKey,
    ) {
        this.bytes = unescapeAndRemoveStartEndBytes().byteArray
        this.crypto = crypto
        this.bytes = escapedBytes.byteArray
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

        this.encryptedFlag = bytes[position].toInt()
        position += 1

        this.contentType = bytes[position].toInt()
        position += 1

        val payLoadSize = getRange(position, position + 2).toInt()
        position += 2

        this.payload = getRange(position, position + payLoadSize)
        position += payLoadSize

        // verify hmac
        hmac = getRange(position, position + 32)

        this.sessionKey = crypto.createSessionKey(senderPrivateKey, targetPublicKey, nonce)
        val verifyHmac = crypto.hmac(sessionKey, getRange(0, size - 32))
        if (verifyHmac != hmac) throw IllegalArgumentException("Invalid HMAC")
    }

    /**
     * The raw command in the payload portion, unencrypted and without 0x36 container.
     *
     * @return The unenncrypted command
     */
    fun getUnecryptedPayload(): Bytes {
        return if (encryptedFlag == 1) {
            val decrypted = crypto.encryptDecrypt(payload, senderPrivateKey, targetPublicKey, nonce)
            decrypted.getRange(4, decrypted.size)
        } else {
            this.payload
        }
    }

    fun getEscapedAndWithStartEndBytes(): Bytes {
        return this.escapeAndAddStartEndBytes()
    }

    /**
     * HM Custom binary command container (0x36), encrypted by HM custom AES (create a secure command
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
        // Builds the container by concatenating <<0x036, 0x01, size of command>> and command
        val commandData = Bytes(4 + message.size)
        commandData.set(0, 0x36)
        commandData.set(1, 0x01)
        commandData.set(2, message.size.toBytes(2))
        commandData.set(4, message)

        val encryptedContainer =
            crypto.encryptDecrypt(
                commandData,
                senderPrivateKey,
                targetPublicKey,
                nonce
            )
        return encryptedContainer
    }

    /**
     * escape the 0x00 bytes and add start/end byte
     * @return The escaped bytes
     */
    private fun Bytes.escapeAndAddStartEndBytes(): Bytes {
        val result = ArrayList<Byte>()

        result.add(0x00)

        for (i in 0..this.size) {
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
     * escape the 0x00 bytes and add start/end byte
     *
     * @return The escaped bytes
     */
    private fun Bytes.unescapeAndRemoveStartEndBytes(): Bytes {
        val result = ArrayList<Byte>()

        if (this[0] != 0x00.toByte()) {
            throw IllegalArgumentException("Invalid start byte")
        }

        if (this[this.size - 1] != 0xFF.toByte()) {
            throw IllegalArgumentException("Invalid end byte")
        }

        for (i in 1 until this.size) {
            if (this[i] != 0xFE.toByte()) {
                result.add(this[i])
            }
        }

        return Bytes(result.toByteArray())
    }
}