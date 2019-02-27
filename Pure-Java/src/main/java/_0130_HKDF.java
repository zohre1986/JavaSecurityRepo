import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.util.encoders.Hex;

public class _0130_HKDF {
    public static void main(String[] args) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());

        // master key
        byte[] mk = Hex.decode("fb17958b2c8a19925e82f8b5d260c89d");

        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        byte[] k3 = new byte[16];


        hkdf.init(new HKDFParameters(mk, null, null));
        hkdf.generateBytes(k1, 0, 16);
        hkdf.generateBytes(k2, 0, 16);
        hkdf.generateBytes(k3, 0, 16);

        System.out.printf("k1 = %s\n", Hex.toHexString(k1));
        System.out.printf("k2 = %s\n", Hex.toHexString(k2));
        System.out.printf("k3 = %s\n", Hex.toHexString(k3));

    }
}
