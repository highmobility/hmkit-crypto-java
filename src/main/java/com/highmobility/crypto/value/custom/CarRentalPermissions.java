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
