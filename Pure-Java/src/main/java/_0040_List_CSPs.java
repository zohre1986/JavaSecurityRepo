import java.security.Provider;
import java.security.Security;
import java.util.Set;

public class _0040_List_CSPs {
    // In Java 9, getVersion() is deprected in favor of getVersionStr()
    @SuppressWarnings("deprecation")
    public static void main(String[] args) {
        Provider[] providers = Security.getProviders();
        int c = 0;

        for (Provider p : providers) {
            System.out.printf("*** %s  |  %s  |  %f\n",
                    p.getName(), p.getInfo(), p.getVersion());

            Set<Provider.Service> services = p.getServices();

            for (Provider.Service s : services) {
                System.out.printf("%04d\t=> %s  |  %s  |  %s\n",
                        c++, s.getType(), s.getAlgorithm(), s.getClassName());
            }
        }
    }
}
