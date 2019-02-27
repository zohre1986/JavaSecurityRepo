import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.invoke.MethodHandles;

public class _0200_PKCS7 {
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_GREEN = "\u001B[32m";


    public static void main(String[] args) throws Exception {
        File f = new File(getResource("google.p7b"));
        byte[] buffer = new byte[(int) f.length()];
        DataInputStream in = new DataInputStream(new FileInputStream(f));
        in.readFully(buffer);
        in.close();

        CMSSignedData cms = new CMSSignedData(buffer);
        Store<X509CertificateHolder> store = cms.getCertificates();

        for (X509CertificateHolder holder : store.getMatches(null)) {
            System.out.printf("%s%s%s -> %s%s%s\n",
                    ANSI_BLUE, holder.getSubject(),
                    ANSI_RESET,
                    ANSI_GREEN, holder.getIssuer(),
                    ANSI_RESET);
        }
    }

    /** @noinspection SameParameterValue*/
    private static String getResource(String name) {
        return MethodHandles.lookup().lookupClass().getResource(name).getFile();
    }
}
