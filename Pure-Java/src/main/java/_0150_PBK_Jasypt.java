import org.jasypt.util.password.StrongPasswordEncryptor;

public class _0150_PBK_Jasypt {
    public static void main(String[] args) {

        StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();
        String encryptedPassword = passwordEncryptor.encryptPassword("A_Simple_Password");

        System.out.println(encryptedPassword);

    }
}
