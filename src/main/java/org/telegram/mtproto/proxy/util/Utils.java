package org.telegram.mtproto.proxy.util;

import java.security.SecureRandom;

/**
 *
 * @author ait
 */
public class Utils {

    private static final SecureRandom secureRandom = new SecureRandom();

    @SuppressWarnings("ManualArrayToCollectionCopy")
    public static byte[] copyByteArray(byte[] source) {
        byte[] dest = new byte[source.length];
        for (int i = 0; i < dest.length; i++) {
            dest[i] = source[i];
        }
        return dest;
    }

    public static byte[] nextRandomBytes(int len) {
        byte[] data = new byte[len];
        secureRandom.nextBytes(data);
        return data;
    }

    public static void changeRandomBytes(byte[] data) {
        secureRandom.nextBytes(data);
    }

    public static byte[] hexStringToByteArray(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static void intToLittleEndian(int i, byte[] buf, int idx) {
        buf[idx + 3] = (byte) (i >> 24);
        buf[idx + 2] = (byte) (i >> 16);
        buf[idx + 1] = (byte) (i >> 8);
        buf[idx] = (byte) i;
    }

    public static int littleEndianToInt(byte[] buf, int offset) {
        return ((buf[offset + 3] & 0xFF) << 24) | ((buf[offset + 2] & 0xFF) << 16) | ((buf[offset + 1] & 0xFF) << 8)
                | (buf[offset] & 0xFF);
    }

    public static void reverseByteArray(byte[] data) {
        for (int i = 0; i < data.length / 2; i++) {
            byte temp = data[i];
            data[i] = data[data.length - i - 1];
            data[data.length - i - 1] = temp;
        }
    }

}
