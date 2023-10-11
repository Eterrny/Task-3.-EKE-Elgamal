import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EKE {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        if (args.length == 0) {
            System.out.println("Входные параметры отсутсвуют");
            return;
        }
//        if (args[0].equals("/help")) {
//            System.out.println("""
//                    Программе должны передаваться следующие параметры:
//                    \t- простое число;
//                    \t- длина ключа в битах (128, 192, 256). Необязательный параметр (значение по умолчанию - 128)""");
//            return;
//        }
        if (args[0].equals("/help")) {
            System.out.println("""
                    Программе должен передаваться следующий параметр:
                    \t- длина простого числа в битах""");
            return;
        }
        BigInteger p;
        try {
            p = BigInteger.ONE.shiftLeft(Integer.parseInt(args[0])).nextProbablePrime();
        } catch (NumberFormatException e) {
            System.out.println("Входные параметры заданы некорректно. Было передано не число.\n" + e.getMessage());
            return;
        }
//        if (!p.isProbablePrime(100)) {
//            throw new IllegalArgumentException("Введенное число не является простым.");
//        }
        int keyLength = 128;
//        if (args.length == 2) {
//            try {
//                keyLength = Integer.parseInt(args[1]);
//            } catch (NumberFormatException e) {
//                System.out.println("Некорректное значение длины ключа, должно быть передано число.");
//                return;
//            }
//        } else {
//            keyLength = 128;
//        }
//        if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
//            throw new IllegalArgumentException("Некорректный ввод. Допустимая длина ключа: 128, 192, 256");
//        }
        EKEService service = new EKEService(p);
    }
}