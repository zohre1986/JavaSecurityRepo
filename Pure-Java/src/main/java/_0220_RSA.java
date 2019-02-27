import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class _0220_RSA {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(1024);
        KeyPair key = kg.genKeyPair();

        System.out.println(key.getPublic());
        System.out.println("-----------------------------------");
        System.out.println(key.getPrivate());
        System.out.println("-----------------------------------");

        // ECB is ignored; see https://crypto.stackexchange.com/q/25899/77
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        rsa.init(Cipher.ENCRYPT_MODE, key.getPublic());

        byte[] ctxt = rsa.doFinal("I love crypto!".getBytes());
        System.out.printf("Ciphertext: %s\n", Hex.toHexString(ctxt));
        System.out.printf("Ciphertext length: %d\n", ctxt.length);

        System.out.println("-----------------------------------");

        rsa.init(Cipher.DECRYPT_MODE, key.getPrivate());

        byte[] ptxt = rsa.doFinal(ctxt);
        System.out.printf("Plaintext: %s\n", new String(ptxt));
    }
}
