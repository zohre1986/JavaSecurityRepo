import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;

public class _0060_Hash_Change {

    public static void main(String[] args) throws Exception {
        String str1 = "This is a simple string";
        String str2 = str1 + "0";

        MessageDigest[] mds = new MessageDigest[]{
                MessageDigest.getInstance("MD5"),
                MessageDigest.getInstance("SHA-1"),
                MessageDigest.getInstance("SHA-256"),
                MessageDigest.getInstance("SHA3-256")
        };

        byte[] b1 = str1.getBytes();
        byte[] b2 = str2.getBytes();

        System.out.printf("%-8s\t%-64s\t%s\n",
                "Algorithm", "Digest 1", "Digest 2");
        System.out.println("-".repeat(145));

        for (MessageDigest md : mds) {
            byte[] hash1 = md.digest(b1);
            byte[] hash2 = md.digest(b2);

            System.out.printf("%-8s\t%-64s\t%s\n",
                    md.getAlgorithm(),
                    Hex.toHexString(hash1),
                    Hex.toHexString(hash2));
        }
    }

}
