package com.highmobility.crypto.value;

import com.highmobility.value.Bytes;
import com.highmobility.value.BytesWithLength;

public class Issuer extends BytesWithLength {
    /**
     * @param value The raw bytes.
     */
    public Issuer(Bytes value) {
        super(value);
    }

    /**
     * @param value The bytes in hex or Base64.
     */
    public Issuer(String value) {
        super(value);
    }

    /**
     * @param bytes The raw bytes.
     */
    public Issuer(byte[] bytes) {
        super(bytes);
    }

    @Override protected int getExpectedLength() {
        return 4;
    }
}
