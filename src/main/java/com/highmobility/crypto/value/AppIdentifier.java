package com.highmobility.crypto.value;

import com.highmobility.value.Bytes;
import com.highmobility.value.BytesWithLength;

public class AppIdentifier extends BytesWithLength {
    /**
     * @param value The raw bytes.
     */
    public AppIdentifier(Bytes value) {
        super(value);
    }

    /**
     * @param value The bytes in hex or Base64.
     */
    public AppIdentifier(String value) {
        super(value);
    }

    /**
     * @param bytes The raw bytes.
     */
    public AppIdentifier(byte[] bytes) {
        super(bytes);
    }

    @Override protected int getExpectedLength() {
        return 12;
    }
}
