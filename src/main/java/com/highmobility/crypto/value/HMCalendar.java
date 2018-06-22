package com.highmobility.crypto.value;

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
        bytes[3] = (byte) (calendar.get(Calendar.HOUR));
        bytes[4] = (byte) (calendar.get(Calendar.MINUTE));

        return bytes;
    }

    @Override protected int getExpectedLength() {
        return 5;
    }
}
