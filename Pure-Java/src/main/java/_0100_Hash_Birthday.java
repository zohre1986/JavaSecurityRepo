import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class _0100_Hash_Birthday {

    public static void main(String[] args) {
        SecureRandom sr = new SecureRandom();
        List<Integer> all = new ArrayList<>();
        int count = 0;

        do {
            int day = sr.nextInt(365);
            if(all.contains(day))
                break;
            all.add(day);
            count++;
        } while (true);

        System.out.printf("It took %d people before a collision happens!\n", count);
    }

}
