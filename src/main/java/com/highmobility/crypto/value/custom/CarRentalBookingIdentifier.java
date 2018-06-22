package com.highmobility.crypto.value.custom;

import com.highmobility.value.BytesWithLength;

public class CarRentalBookingIdentifier extends BytesWithLength {
    /**
     * @param value The bytes in hex or Base64.
     */
    public CarRentalBookingIdentifier(String value) {
        super(value);
    }

    /**
     * @param bytes The raw bytes.
     */
    public CarRentalBookingIdentifier(byte[] bytes) {
        super(bytes);
    }

    @Override protected int getExpectedLength() {
        return 6;
    }
}
