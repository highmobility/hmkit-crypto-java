package com.highmobility.crypto.value;

import com.highmobility.value.Bytes;
import com.highmobility.value.BytesWithLength;

public class Sha256 extends BytesWithLength {
    /**
     * @param value The raw bytes.
     */
    public Sha256(Bytes value) {
        super(value);
    }

    /**
     * @param value The bytes in hex or Base64.
     */
    public Sha256(String value) {
        super(value);
    }

    /**
     * @param bytes The raw bytes.
     */
    public Sha256(byte[] bytes) {
        super(bytes);
    }

    @Override protected int getExpectedLength() {
        return 32;
    }
}
