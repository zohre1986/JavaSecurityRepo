import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.MessageDigest;
import java.util.Arrays;

public class _0090_Hash_SHA1_Collision {

    // http://shattered.io/
    public static void main(String[] args) throws Exception {
        byte[] f1 = getFile("shattered-1.pdf");
        byte[] f2 = getFile("shattered-2.pdf");

        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        System.out.printf("f1 %s f2\n", Arrays.equals(f1, f2) ? "==" : "!=");

        byte[] hash1 = sha1.digest(f1);
        byte[] hash2 = sha1.digest(f2);

        System.out.println(Hex.toHexString(hash1));
        System.out.println(Hex.toHexString(hash2));
    }

    private static byte[] getFile(String fileName) throws IOException {
        return IOUtils.toByteArray(MethodHandles.lookup().lookupClass()
                .getResource(fileName));
    }

}
