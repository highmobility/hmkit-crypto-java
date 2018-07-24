package com.highmobility.test;

import com.highmobility.crypto.value.DeviceSerial;
import com.highmobility.crypto.value.HMCalendar;
import com.highmobility.crypto.value.Permissions;

import org.junit.Test;

import java.util.Arrays;
import java.util.Calendar;

import static junit.framework.TestCase.assertTrue;

public class ValueTest {
    @Test public void serial() {
        DeviceSerial serial = new DeviceSerial("000000000000000000");
        assertTrue(Arrays.equals(serial.getByteArray(), new byte[]{0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00}));
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

    @Test public void calendar() {
        HMCalendar calendar = new HMCalendar("0701020E07");
        Calendar date = calendar.getCalendar();
        assertTrue(date.get(Calendar.YEAR) == 2007);
        assertTrue(date.get(Calendar.MONTH) == 0);
        assertTrue(date.get(Calendar.DAY_OF_MONTH) == 2);
        assertTrue(date.get(Calendar.HOUR_OF_DAY) == 14);
        assertTrue(date.get(Calendar.MINUTE) == 7);
    }
}