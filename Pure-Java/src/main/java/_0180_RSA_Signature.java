import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class _0180_RSA_Signature {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(1024);
        KeyPair key = kg.genKeyPair();

        System.out.println(key.getPublic());
        System.out.println("-".repeat(30));
        System.out.println(key.getPrivate());
        System.out.println("-".repeat(30));

        // RSA-PSS, a very secure variant of RSA signature
        // See: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
        Signature rsa_pss = Signature.getInstance("SHA256withRSAandMGF1", "BC");

        byte[] data = "I love crypto!".getBytes();

        rsa_pss.initSign(key.getPrivate());
        rsa_pss.update(data);
        byte[] signature = rsa_pss.sign();

        System.out.printf("Signature: %s\n", Hex.toHexString(signature));
        System.out.printf("Signature length: %d\n", signature.length);

        System.out.println("-".repeat(30));

        rsa_pss.initVerify(key.getPublic());
        rsa_pss.update(data);
        boolean valid1 = rsa_pss.verify(signature);
        System.out.printf("Signature validated: %b\n", valid1);

        System.out.println("-".repeat(30));

        data[0] &= 1;
        rsa_pss.update(data);
        boolean valid2 = rsa_pss.verify(signature);
        System.out.printf("Signature validated: %b\n", valid2);
    }
}
