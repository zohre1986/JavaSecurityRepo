import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class _0160_AES_GCM {

    private static final String ANSI_RED = "\u001B[31m";

    // AES-GCM parameters
    private static final int AES_KEY_SIZE = 128; // in bits
    private static final int GCM_NONCE_LENGTH = 12; // in bytes. 12 is the recommended value.
    private static final int GCM_TAG_LENGTH = 16 * 8; // in bits

    public static void main(String[] args) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        (new SecureRandom()).nextBytes(nonce);
        GCMParameterSpec gps = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey key = kg.generateKey();

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key, gps);

        byte[] ctxt = aes.doFinal("Hello".getBytes());

        System.out.printf("Ciphertext: %s\n", Hex.toHexString(ctxt));

        aes.init(Cipher.DECRYPT_MODE, key, gps);

        byte[] ptxt = aes.doFinal(ctxt);
        System.out.printf("Plaintext: %s\n", new String(ptxt));

        try {
            ctxt[5] &= 1;
            ptxt = aes.doFinal(ctxt);
            System.out.println(new String(ptxt));
        }  catch (Exception ex) {
            System.out.println(ANSI_RED + "Decryption error: " + ex.getMessage());
        }
    }
}
