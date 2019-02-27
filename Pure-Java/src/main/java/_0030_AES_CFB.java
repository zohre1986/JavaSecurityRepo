import org.bouncycastle.util.encoders.Hex;
import utils.RawConsoleInput;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class _0030_AES_CFB {

    public static void main(String[] args) throws Exception {
        byte[] iv = new byte[16];
        (new SecureRandom()).nextBytes(iv);
        IvParameterSpec ips = new IvParameterSpec(iv);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        Cipher aes = Cipher.getInstance("AES/CFB8/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key, ips);

        while (true) {
            System.out.print("Enter a character to encrypt: ");
            int b = RawConsoleInput.read(true);
            System.out.println((char) b);
            if (b == 13)    // Enter pressed
                break;

            byte[] ptxt = new byte[]{(byte) b};
            byte[] ctxt = aes.update(ptxt);

            System.out.printf("Ciphertext: %s\n", Hex.toHexString(ctxt));
        }
    }
}
