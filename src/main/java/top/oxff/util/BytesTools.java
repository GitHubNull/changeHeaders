package top.oxff.util;

public class BytesTools {
    public static byte[] subByteArray(byte[] src, int off, int length) {
        byte[] ret = new byte[length];
        System.arraycopy(src, off, ret, 0, length);

        return ret;
    }
}
