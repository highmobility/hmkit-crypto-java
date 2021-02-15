import com.highmobility.value.Bytes
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
    val length = Math.min(biBytes.size, numBytes)
    System.arraycopy(biBytes, start, bytes, numBytes - length, length)
    return Bytes(bytes)
}