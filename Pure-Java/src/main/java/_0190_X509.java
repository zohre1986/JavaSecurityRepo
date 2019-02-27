import java.io.FileInputStream;
import java.lang.invoke.MethodHandles;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class _0190_X509 {
    public static void main(String[] args) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream in = new FileInputStream(getResource("google.cer"));
        X509Certificate google_cert = (X509Certificate) cf.generateCertificate(in);

        System.out.println(google_cert.toString());
    }

    /** @noinspection SameParameterValue*/
    private static String getResource(String name) {
        return MethodHandles.lookup().lookupClass().getResource(name).getFile();
    }
}
