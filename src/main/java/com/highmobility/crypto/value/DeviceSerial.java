package com.highmobility.crypto.value;

import com.highmobility.value.Bytes;
import com.highmobility.value.BytesWithLength;

public class DeviceSerial extends BytesWithLength {

    /**
     * @param value The raw bytes.
     */
    public DeviceSerial(Bytes value) {
        super(value);
    }

    /**
     * @param value The bytes in hex or Base64.
     */
    public DeviceSerial(String value) {
        super(value);
    }

    /**
     * @param bytes The raw bytes.
     */
    public DeviceSerial(byte[] bytes) {
        super(bytes);
    }

    @Override protected int getExpectedLength() {
        return 9;
    }
}
