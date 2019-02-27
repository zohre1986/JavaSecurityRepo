import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class _0050_Stream_Ciphers {

    public static void main(String[] args) throws Exception {
        Cipher salsa20 = Cipher.getInstance("SALSA20", "BC");
        Cipher rc4 = Cipher.getInstance("RC4", "BC");
        Cipher aes = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        byte[] _16_zeros = new byte[16]; // Bad; just for test!
        byte[] _08_zeros = new byte[8]; // Bad; just for test!

        Key key = new SecretKeySpec(_16_zeros, "SALSA20");
        IvParameterSpec ips = new IvParameterSpec(_08_zeros);

        System.out.printf("Key length is: %d bytes\n", key.getEncoded().length);

        salsa20.init(Cipher.ENCRYPT_MODE, key, ips);
        byte[] ctxt = salsa20.doFinal(new byte[4]);

        System.out.printf("Ciphertext: %s\n", Hex.toHexString(ctxt));

        System.out.println("---------------------------");

        rc4.init(Cipher.ENCRYPT_MODE, key);
        aes.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(_16_zeros));

        byte[] largePtxt = new byte[1 << 28];

        speedTest(rc4, largePtxt);
        speedTest(salsa20, largePtxt);
        speedTest(aes, largePtxt);
    }

    private static void speedTest(Cipher cipher, byte[] largePtxt) throws Exception {
        long start = System.nanoTime();
        cipher.doFinal(largePtxt);
        long end = System.nanoTime();
        System.out.printf("%s took %f seconds.\n", cipher.getAlgorithm(), (end - start) / 1E9);
    }

}
