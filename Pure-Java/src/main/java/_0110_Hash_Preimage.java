import java.security.MessageDigest;
import java.security.SecureRandom;
import org.bouncycastle.util.encoders.Hex;

/**
 * @noinspection SameParameterValue
 */
public class _0110_Hash_Preimage {

    public static void main(String[] args) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        SecureRandom sr = new SecureRandom();

        byte[] msg = new byte[32];
        String digest;
        int count = 0;

        do {
            sr.nextBytes(msg);
            digest = Hex.toHexString(sha256.digest(msg));
            count++;
        } while (!digest.endsWith("0".repeat(3)));

        System.out.printf("message\t= %s\ndigest\t= %s\ncount\t= %d\n",
                Hex.toHexString(msg), digest, count);
    }

}
