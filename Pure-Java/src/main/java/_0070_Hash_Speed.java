import java.security.MessageDigest;

import static utils.Formatter.humanReadableByteCount;

public class _0070_Hash_Speed {

    private static MessageDigest[] mds;

    public static void main(String[] args) throws Exception {
        mds = new MessageDigest[]{
                MessageDigest.getInstance("MD5"),
                MessageDigest.getInstance("SHA-1"),
                MessageDigest.getInstance("SHA-256"),
                MessageDigest.getInstance("SHA-512"),
                MessageDigest.getInstance("SHA-512/256"),
                MessageDigest.getInstance("SHA3-256"),
                MessageDigest.getInstance("SHA3-512")
        };

        computeHashTime(16, 1 << 10);
        System.out.println();
        computeHashTime(1 << 28, 1);
    }

    private static void computeHashTime(int inLen, int count) {
        long start, end;
        byte[] bytes = new byte[inLen];

        System.out.printf("Computations for input lenght %s...\n",
                humanReadableByteCount(inLen));

        System.out.printf("%-10s\t%s\t%s\n",
                "Algorithm", "Length (bits)", "Time (seconds)");
        System.out.println("-".repeat(45));

        for (var md : mds) {
            start = System.nanoTime();
            for (int i = 0; i < count; i++)
                md.digest(bytes);
            end = System.nanoTime();

            System.out.printf("%-10s\t%-13s\t%s\n",
                    md.getAlgorithm(),
                    md.getDigestLength() * 8,
                    (end - start) / 1E9 / count);
        }
    }

}
