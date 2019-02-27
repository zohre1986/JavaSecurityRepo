import java.io.FileInputStream;
import java.lang.invoke.MethodHandles;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

public class _0210_Cert_Path_Validation {

    private static KeyStore ks;

    public static void main(String[] args) throws Exception {
        /* ===============================================
         *         See Oracle's documentation:
         *         "Java PKI Programmer's Guide"
         *         https://dousti.page.link/java-pki
         * ===============================================
         */
        Security.setProperty("ocsp.enable", "true");
        // Security.setProperty("ocsp.responderURL", ...)
        // Security.setProperty("ocsp.responderCertSubjectName", ...);

        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        System.setProperty("com.sun.security.enableCRLDP", "true");


        /* ===============================================
         *         Load KeyStore from the disk
         * ===============================================
         */
        ks = loadKeyStore();

        /* ===============================================
         *      Set the "Target Cert" which
         *      we are going to validate
         * ===============================================
         */
        X509CertSelector selector = new X509CertSelector();
        X509Certificate target = getX509("google");
        selector.setCertificate(target);

        /* ===============================================
         *      Load all certificates into a "Store"
         *      They might be required along the path
         *      from "Target" to "Root"
         * ===============================================
         */
        List<X509Certificate> all = new ArrayList<>();
        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements())
            all.add(getX509(aliases.nextElement()));

        CertStore cs = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(all));

        ArrayList<CertStore> certStores = new ArrayList<>();
        certStores.add(cs);

        /* ===============================================
         *      Set the "Trust Anchors" based on
         *      one or more root certificates
         * ===============================================
         */
        X509Certificate root = getX509("root");
        Set<TrustAnchor> anchors = Collections.singleton(
                new TrustAnchor(root, null));

        /* ===============================================
         *      Ask Java to build the certificate path,
         *      starting from "Target",
         *      and all the way to the "Root"
         * ===============================================
         */

        PKIXBuilderParameters pbParams = new PKIXBuilderParameters(anchors, selector);
        pbParams.setCertStores(certStores);

        // Uncomment if you are not online!
        // pbParams.setRevocationEnabled(false);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
        CertPathBuilderResult cpbResult = cpb.build(pbParams);

        /* ===============================================
         *      Ask Java to validate the certificate path
         * ===============================================
         */

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        CertPathValidatorResult result = cpv.validate(cpbResult.getCertPath(), pbParams);
        System.out.println(result);
    }

    private static KeyStore loadKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        char[] integrity_password = "MyPassword".toCharArray();
        String path = MethodHandles.lookup().lookupClass().getResource("store.jks").getFile();

        ks.load(new FileInputStream(path), integrity_password);
        return ks;
    }

    private static X509Certificate getX509(String alias) throws Exception {
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (cert == null)
            throw new NullPointerException("The store does not have a certificate with alias " + alias);
        return cert;
    }

}
