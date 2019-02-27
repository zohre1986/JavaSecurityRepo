import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

public class _0185_ECC_Signature {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("EC");
        kg.initialize(256);
        KeyPair key = kg.genKeyPair();

        System.out.println(key.getPublic());
        System.out.println("-".repeat(30));
        System.out.println(key.getPrivate());
        ECPrivateKey sk = (ECPrivateKey) key.getPrivate();
        System.out.printf("Private key parameter S = %s\n", sk.getS());
        System.out.println("-".repeat(30));

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        System.out.println(ecdsa.getProvider());
        System.out.println("-".repeat(30));

        byte[] data = "I love crypto!".getBytes();

        ecdsa.initSign(key.getPrivate());
        ecdsa.update(data);
        byte[] signature = ecdsa.sign();

        System.out.printf("Signature: %s\n", Hex.toHexString(signature));
        System.out.printf("Signature length: %d\n", signature.length);

        System.out.println("-".repeat(30));

        ecdsa.initVerify(key.getPublic());
        ecdsa.update(data);
        boolean valid1 = ecdsa.verify(signature);
        System.out.printf("Signature validated: %b\n", valid1);

        System.out.println("-".repeat(30));

        data[0] &= 1;
        ecdsa.update(data);
        boolean valid2 = ecdsa.verify(signature);
        System.out.printf("Signature validated: %b\n", valid2);
    }
}
