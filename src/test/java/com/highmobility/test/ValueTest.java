package com.highmobility.test;

import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.Permissions;

import org.junit.Test;

import java.util.Arrays;

import static junit.framework.TestCase.assertTrue;

public class ValueTest {
    @Test public void serial() {
        DeviceSerial serial = new DeviceSerial("000000000000000000");
        assertTrue(Arrays.equals(serial.getByteArray(), new byte[] {0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }));
    }

    @Test(expected = IllegalArgumentException.class)
    public void ivalidLengthThrow() {
        new DeviceSerial("00");
    }

    @Test(expected = IllegalArgumentException.class)
    public void ivalidRangeThrow() {
        new Permissions("0011334400113344001133440011334477");
    }

    @Test
    public void maxLengthNotThrow() {
        new Permissions("1007FFFDFFEFFFFFFF03000000000000");
    }
}