import java.io.FileInputStream;
import java.lang.invoke.MethodHandles;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class _0240_PKCS12 {
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_BLUE = "\u001B[34m";

    // COMMAND LINE:
    // keytool -list -keystore dousti.p12 -storepass my_secure_password -v

    public static void main(String[] args) throws Exception {
        FileInputStream in = new FileInputStream(getResource("sadeq.p12"));
        char[] integrity_password = "my_secure_password".toCharArray();
        char[] entry_password = "dousti-entry-password".toCharArray();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(in, integrity_password);

        var aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            System.out.printf("%s****** Alias: \"%s\" ******%s\n", ANSI_BLUE, alias, ANSI_RESET);

            Entry keyEntry = keyStore.getEntry(alias,
                    new PasswordProtection(entry_password));

            if (!(keyEntry instanceof PrivateKeyEntry))
                continue;

            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyEntry;

            System.out.println(privateKeyEntry);

            PublicKey pk = privateKeyEntry.getCertificate().getPublicKey();
            if (pk instanceof RSAPublicKey) {

                System.out.printf("%sRSA public exponent  (e) = %s\n",
                        ANSI_BLUE,
                        ((RSAPublicKey) pk).getPublicExponent());

                RSAPrivateKey sk = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

                System.out.printf("RSA private exponent (d) = %s\n",
                        sk.getPrivateExponent());
            }
        }
    }

    /** @noinspection SameParameterValue*/
    private static String getResource(String name) {
        return MethodHandles.lookup().lookupClass().getResource(name).getFile();
    }
}
