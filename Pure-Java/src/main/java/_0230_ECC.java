import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class _0230_ECC {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("EC");
        kg.initialize(256);
        KeyPair key = kg.genKeyPair();

        ECPublicKey pk = (ECPublicKey) key.getPublic();
        System.out.println(pk);
        System.out.println("-----------------------------------");

        ECPrivateKey sk = (ECPrivateKey) key.getPrivate();

        System.out.printf("Private key parameter S = %s\n", sk.getS());
        System.out.println("-----------------------------------");

        Cipher iesCipher = Cipher.getInstance("ECIES");
        iesCipher.init(Cipher.ENCRYPT_MODE, pk);
        byte[] ctxt = iesCipher.doFinal("Hello, world!".getBytes());

        System.out.printf("Ciphertext = %s\n", Hex.toHexString(ctxt));

        iesCipher.init(Cipher.DECRYPT_MODE, sk);
        byte[] ptxt = iesCipher.doFinal(ctxt);
        System.out.printf("Plaintext = %s\n", new String(ptxt));
    }
}
