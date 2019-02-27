import org.bouncycastle.util.encoders.Hex;
import utils.Pair;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Scanner;

public class _0020_AES_CBC {

    private static Pair encrypt(Cipher cipher, String plaintext, Key key) throws Exception {
        byte[] iv = new byte[16];
        (new SecureRandom()).nextBytes(iv);
        IvParameterSpec ips = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ips);

        byte[] ctxt = cipher.doFinal(plaintext.getBytes());

        return new Pair(iv, ctxt);
    }

    private static String decrypt(Cipher cipher, Pair pair, Key key) throws Exception {
        IvParameterSpec ips = new IvParameterSpec(pair.getIv());

        cipher.init(Cipher.DECRYPT_MODE, key, ips);

        byte[] ptxt = cipher.doFinal(pair.getCtxt());

        return new String(ptxt);
    }

    public static void main(String[] args) throws Exception {
        // Security.setProperty("crypto.policy", "limited");

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");

        System.out.print("Enter plaintext: ");
        Scanner scanner = new Scanner(System.in);
        String ptxt = scanner.nextLine();

        Pair pair = encrypt(aes, ptxt, key);

        System.out.printf("Ciphertext: %s\n", Hex.toHexString(pair.getCtxt()));
        System.out.printf("Ciphertext length: %d\n", pair.getCtxt().length);

        System.out.printf("Plaintext: %s\n", decrypt(aes, pair, key));
    }
}
