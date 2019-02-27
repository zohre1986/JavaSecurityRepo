import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.MessageDigest;
import java.util.Arrays;

public class _0080_Hash_MD5_Collision {

    // https://www.mscs.dal.ca/~selinger/md5collision/
    public static void main(String[] args) throws Exception {
        byte[] f1 = getFile("angel.exe");
        byte[] f2 = getFile("evil.exe");

        MessageDigest md5 = MessageDigest.getInstance("MD5");

        System.out.printf("f1 %s f2\n", Arrays.equals(f1, f2) ? "==" : "!=");

        byte[] hash1 = md5.digest(f1);
        byte[] hash2 = md5.digest(f2);

        System.out.println(Hex.toHexString(hash1));
        System.out.println(Hex.toHexString(hash2));
    }

    private static byte[] getFile(String fileName) throws IOException {
        return IOUtils.toByteArray(MethodHandles.lookup().lookupClass()
                .getResource(fileName));
    }

}
