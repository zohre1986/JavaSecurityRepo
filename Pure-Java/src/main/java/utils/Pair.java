package utils;

public class Pair {
    private byte[] iv;
    private byte[] ctxt;

    public Pair(byte[] iv, byte[] ctxt) {
        this.iv = iv;
        this.ctxt = ctxt;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCtxt() {
        return ctxt;
    }
}
