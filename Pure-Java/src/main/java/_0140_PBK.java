import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class _0140_PBK {
    public static void main(String[] args) throws Exception {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        String password = "A_Simple_Password";

        KeySpec keySpec = new PBEKeySpec(password.toCharArray(),
                salt, 1000, 128);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = skf.generateSecret(keySpec);

        System.out.printf("$6$%s$%s\n",
                Base64.toBase64String(salt),
                Base64.toBase64String(key.getEncoded()));
    }
}
