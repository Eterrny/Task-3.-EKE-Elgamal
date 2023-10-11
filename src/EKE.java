import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class EKE {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        if (args.length == 0) {
            System.out.println("Входные параметры отсутсвуют");
            return;
        }
        if (args[0].equals("/help")) {
            System.out.println("""
                    Программе должен передаваться следующий параметр:
                    \t- длина простого числа в битах""");
            return;
        }
        BigInteger p;
        try {
            Random rnd = new Random();
            p = BigInteger.probablePrime(Integer.parseInt(args[0]), rnd);
        } catch (NumberFormatException e) {
            System.out.println("Входные параметры заданы некорректно. Было передано не число.\n" + e.getMessage());
            return;
        }
        int keyLength = 128;
        EKEService service = new EKEService(p);
    }
}