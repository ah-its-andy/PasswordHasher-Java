package io.standardcore.security;

public class BufferUtil {
    public static void writeNetworkByteOrder(byte[] buffer, int offset, int value)
    {
        buffer[offset + 0] = (byte) (value >> 24);
        buffer[offset + 1] = (byte) (value >> 16);
        buffer[offset + 2] = (byte) (value >> 8);
        buffer[offset + 3] = (byte) (value >> 0);
    }

    public static int readNetworkByteOrder(byte[] buffer, int offset)
    {
        return ((int) buffer[offset + 0] << 24)
                | ((int) buffer[offset + 1] << 16)
                | ((int) buffer[offset + 2] << 8)
                | buffer[offset + 3];
    }

    public static boolean byteArraysEqual(byte[] a, byte[] b)
    {
        if (a == null && b == null)
            return true;
        if (a == null || b == null || a.length != b.length)
            return false;
        boolean areSame = true;
        for (int i = 0; i < a.length; i++)
            areSame &= a[i] == b[i];
        return areSame;
    }

    public static void blockFill(byte[] src, byte[] dest, int offset)
    {
        System.arraycopy(src,0,dest, offset, src.length);;
    }

    public static void blockCopy(byte[] src, int srcOffset, byte[] dest, int destOffset, int length){
        System.arraycopy(src, srcOffset, dest, destOffset, length);
    }
}
