/*
 * The MIT License
 *
 * Copyright (c) 2014- High-Mobility GmbH (https://high-mobility.com)
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
package com.highmobility.crypto.value.custom;

import com.highmobility.crypto.value.Permissions;
import com.highmobility.utils.ByteUtils;
import com.highmobility.value.BitLocation;

/**
 * Custom permissions for car rental.
 */
public class CarRentalPermissions extends Permissions {
    public CarRentalPermissions() {
        super(Type.CAR_RENTAL);
    }

    public void allowAutoApiRead(boolean allow) {
        allow(new BitLocation(2, 0), allow);
    }

    public void allowAutoApiWrite(boolean allow) {
        allow(new BitLocation(2, 1), allow);
    }

    public void allowDoorLocksWrite(boolean allow) {
        allow(new BitLocation(2, 2), allow);
    }

    public void allowEngineWrite(boolean allow) {
        allow(new BitLocation(2, 3), allow);
    }

    public void allowTheftAlarmWrite(boolean allow) {
        allow(new BitLocation(2, 4), allow);
    }

    public void setBookingIdentifier(CarRentalBookingIdentifier bookingIdentifier) {
        ByteUtils.setBytes(bytes, bookingIdentifier.getByteArray(), 10);
    }
}
