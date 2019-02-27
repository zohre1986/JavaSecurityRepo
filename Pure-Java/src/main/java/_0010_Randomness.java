import java.security.SecureRandom;
import java.util.Random;

public class _0010_Randomness {

    private static void computeTime(Random gen) {
        long start, end;
        byte[] b = new byte[1 << 26];

        start = System.nanoTime();
        gen.nextBytes(b);
        end = System.nanoTime();

        String name = (gen instanceof SecureRandom) ?
                " with algorithm " + ((SecureRandom) gen).getAlgorithm() : "";

        System.out.printf("%s took %f seconds\n",
                gen.getClass() + name,
                (end - start) / 1E9);
    }


    public static void main(String[] args) throws Exception {
        computeTime(new Random());
        computeTime(new SecureRandom());

        // getInstanceStrong() added in Java 1.8
        // Extremely fast on Windows - even faster than Random()
        // Stalled on Linux - don't know why?!
        computeTime(SecureRandom.getInstanceStrong());
    }
}
