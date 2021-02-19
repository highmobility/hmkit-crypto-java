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
package com.highmobility.cryptok.value;

import com.highmobility.value.Bytes;
import com.highmobility.value.BytesWithLength;

import java.util.Calendar;
import java.util.TimeZone;

public class HMCalendar extends BytesWithLength {
    Calendar calendar;

    /**
     * @return The calendar.
     */
    public Calendar getCalendar() {
        return calendar;
    }

    /**
     * @param value The raw bytes.
     */
    public HMCalendar(Bytes value) {
        super(value);
    }

    /**
     * @param value The bytes in hex or Base64.
     */
    public HMCalendar(String value) {
        super(value);
        setCalendar();
    }

    /**
     * @param bytes The raw bytes.
     */
    public HMCalendar(byte[] bytes) {
        super(bytes);
        setCalendar();
    }

    /**
     * @param calendar The calendar.
     */
    public HMCalendar(Calendar calendar) {
        super(bytesFromDate(calendar));
        this.calendar = calendar;
    }

    void setCalendar() {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.setTimeInMillis(0);
        cal.set(2000 + bytes[0], bytes[1] - 1, bytes[2], bytes[3], bytes[4]);
        this.calendar = cal;
    }

    static byte[] bytesFromDate(Calendar calendar) {
        byte[] bytes = new byte[5];

        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));

        bytes[0] = (byte) (calendar.get(Calendar.YEAR) - 2000);
        bytes[1] = (byte) (calendar.get(Calendar.MONTH) + 1);
        bytes[2] = (byte) (calendar.get(Calendar.DAY_OF_MONTH));
        bytes[3] = (byte) (calendar.get(Calendar.HOUR_OF_DAY));
        bytes[4] = (byte) (calendar.get(Calendar.MINUTE));

        return bytes;
    }

    @Override protected int getExpectedLength() {
        return 5;
    }
}
