import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class _0170_AES_GCM_Speed {
    // AES-GCM parameters
    private static final int AES_KEY_SIZE = 128; // in bits
    private static final int AES_COUNTER_SIZE = 8; // in bytes
    private static final int GCM_NONCE_LENGTH = 12; // in bytes. 12 is the recommended value.
    private static final int GCM_TAG_LENGTH = 16 * 8; // in bits

    public static void main(String[] args) throws Exception {
        SecureRandom sr = new SecureRandom();

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey key = kg.generateKey();

        byte[] counter = new byte[AES_COUNTER_SIZE];
        sr.nextBytes(counter);
        IvParameterSpec ips = new IvParameterSpec(counter);
        Cipher aes_ctr = Cipher.getInstance("AES/CTR/NoPadding");
        aes_ctr.init(Cipher.ENCRYPT_MODE, key, ips);


        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        sr.nextBytes(nonce);
        GCMParameterSpec gps = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        Cipher aes_gcm = Cipher.getInstance("AES/GCM/NoPadding");
        aes_gcm.init(Cipher.ENCRYPT_MODE, key, gps);

        speedTest(aes_ctr);
        speedTest(aes_gcm);
    }

    private static void speedTest(Cipher cipher) throws Exception {
        byte[] ptxt = new byte[1 << 20];
        long start, end;
        start = System.nanoTime();
        cipher.doFinal(ptxt);
        end = System.nanoTime();

        System.out.printf("%s took %f seconds.\n",
                cipher.getAlgorithm(),
                (end - start) / 1E9);
    }
}
