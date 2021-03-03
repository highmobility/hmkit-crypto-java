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