package com.highmobility.crypto.value;

import com.highmobility.value.BytesWithLength;

public class PrivateKey extends BytesWithLength {
    /**
     * @param value The bytes in hex or Base64.
     */
    public PrivateKey(String value) {
        super(value);
    }

    /**
     * @param bytes The raw bytes.
     */
    public PrivateKey(byte[] bytes) {
        super(bytes);
    }

    @Override protected int getExpectedLength() {
        return 32;
    }
}
