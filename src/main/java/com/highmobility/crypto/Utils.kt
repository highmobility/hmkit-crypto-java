/*
 * The MIT License
 *
 * Copyright (c) 2023- High-Mobility GmbH (https://high-mobility.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.highmobility.crypto

import com.highmobility.value.Bytes
import java.lang.IllegalArgumentException
import java.math.BigInteger

fun BigInteger.toBytes(): Bytes {
    var data = this.toByteArray()
    if (data.size != 1 && data[0] == 0.toByte()) {
        val tmp = ByteArray(data.size - 1)
        System.arraycopy(data, 1, tmp, 0, tmp.size)
        data = tmp
    }
    return Bytes(data)
}

// prepend 00 if numBytes bigger. remove from beginning if numBytes smaller
fun BigInteger.toBytes(numBytes: Int): Bytes {
    val bytes = ByteArray(numBytes)
    val biBytes = this.toByteArray()
    val start = if (biBytes.size == numBytes + 1) 1 else 0
    val length = biBytes.size.coerceAtMost(numBytes)
    System.arraycopy(biBytes, start, bytes, numBytes - length, length)
    return Bytes(bytes)
}

// Fill with 0-s until blockSize or blockSize * multiplier until bigger or equal to current array.
fun Bytes.fillWith0sUntil(blockSize: Int): Bytes {
    return if (this.length % blockSize == 0) {
        this
    } else {
        val sizeToFill = blockSize - this.length % blockSize
        Bytes(this.byteArray + ByteArray(sizeToFill))
    }
}

/**
 * This works for both negative and positive ints.
 *
 * @param length the returned byte[] length
 * @return the allBytes representing the valueBytes
 */
fun Int.toBytes(length: Int): ByteArray {
    if (length == 1) return byteArrayOf(this.toByte())
    val bytes = BigInteger.valueOf(this.toLong()).toByteArray()
    return if (bytes.size == length) {
        bytes
    } else if (bytes.size < length) {
        // put the allBytes to last elements
        val withZeroBytes = ByteArray(length)
        for (i in bytes.indices) {
            withZeroBytes[length - 1 - i] = bytes[bytes.size - 1 - i]
        }
        withZeroBytes
    } else {
        throw IllegalArgumentException()
    }
}

fun Bytes.toInt(): Int {
    return this.getUnsignedInt(0, size)
}

fun Boolean.toByte(): Byte {
    return when (this) {
        true -> 0x01
        else -> 0x00
    }
}

fun Byte.toBoolean(): Boolean {
    return when (this) {
        0x00.toByte() -> false
        else -> true
    }
}

fun Bytes.getUnsignedInt(at: Int, length: Int): Int {
    if (this.size >= at + length) {
        when (length) {
            4 -> {
                return 0xFF and this[at].toInt() shl 24 or (0xFF and this[at + 1].toInt() shl 16) or
                        (0xFF and this[at + 2].toInt() shl 8) or (0xFF and this[at + 3].toInt())
            }
            3 -> {
                return this[at].toInt() and 0xff shl 16 or (this[at + 1].toInt() and 0xff shl 8) or (this[at + 2].toInt()
                        and 0xff)
            }
            2 -> {
                return this[at].toInt() and 0xff shl 8 or (this[at + 1].toInt() and 0xff)
            }
            1 -> {
                return this[at].toInt() and 0xff
            }
        }
    }
    throw IllegalArgumentException()
}

fun byteArrayOfInts(vararg ints: Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }
