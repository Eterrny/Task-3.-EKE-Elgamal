import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;


public class EKEService {
    public BigInteger p, g;
    Participant alice, bob;


    public Participant getBob() {
        return bob;
    }

    public Participant getAlice() {
        return alice;
    }

    public EKEService(BigInteger p) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        this.p = p;
        this.g = generatePrimitiveRoot(p);
        AESService aes = new AESService();
        this.alice = new Participant("Алиса", p, g, aes);
        this.bob = new Participant("Боб", p, g, aes);
        System.out.printf("%s и %s имеют общий пароль P = %s\n", alice.getName(), bob.getName(), AESService.convertSecretKeyToString(aes.getPublicKey()));
        System.out.printf("По схеме Эль-Гамаля были выбраны p = %s и g = %s\n", p, g);
        this.step1();
    }

    private void step1() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        System.out.println("\n--- Шаг 1 ---");
        System.out.printf("%s выбирает закрытый ключ r = %d\n", alice.getName(), alice.getPrivateElGamalKey());
        System.out.printf("""
                %s посылает пользователю %s следующее сообщение:
                \t- %s
                \t- Открытый ключ yA =  %s\n""", alice.getName(), bob.getName(), alice.getName(), alice.getY());
        this.step2(alice.getName(), alice.getY());
    }

    private void step2(String alice, BigInteger y) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        System.out.println("\n--- Шаг 2 ---");
        bob.generateSessionKey(p);
        System.out.printf("%s делает следующее:\n", bob.getName());
        System.out.printf("\tгенерирует сеансовый ключ К = %s\n", bob.getSessionKeyInt());
        System.out.printf("\tвыбирает закрытый ключ R = %d\n", bob.getPrivateElGamalKey());
        BigInteger kyR = bob.getSessionKeyInt().multiply(y.modPow(bob.getPrivateElGamalKey(), p)).mod(p);
        System.out.printf("\tвычисляет K * yA^R mod p = %d\n", kyR);
        String encBobPublicKey = bob.getEncrypted(bob.getY().toString(), bob.getService().getPublicKey());
        System.out.printf("\tзашифровывает свой открытый ключ %d и получает %s\n", bob.getY(), encBobPublicKey);
        String encKYR = bob.getEncrypted(kyR.toString(), bob.getService().getPublicKey());
        System.out.printf("\tзашифровывает K * yA^R mod p и получает %s\n", encKYR);
        System.out.printf("""
                %s посылает пользователю %s следующее сообщение:
                \t- %s
                \t- %s\n""", bob.getName(), this.alice.getName(), encBobPublicKey, encKYR);
        this.step3(encBobPublicKey, encKYR);
    }

    private void step3(String encBobPublicKey, String encKYR) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("\n--- Шаг 3 ---");
        BigInteger decBobPublicKey = new BigInteger(alice.getDecrypted(encBobPublicKey, alice.getService().getPublicKey()));
        BigInteger decKYR = new BigInteger(alice.getDecrypted(encKYR, alice.getService().getPublicKey()));
        System.out.printf("%s делает следующее:\n", alice.getName());
        System.out.printf("""
                \tрасшировывает сообщение и получает:
                \t\t- %d
                \t\t- %d\n""", decBobPublicKey, decKYR);
        BigInteger k = decKYR.multiply((decBobPublicKey.modPow(alice.getPrivateElGamalKey(), p)).modInverse(p)).mod(p);
        alice.setSessionKey(k);
        System.out.printf("\tвычисляет ключ К и получает %d\n", k);
        alice.generateString();
        System.out.printf("\tгенерирует случайную строку Ra = %s\n", alice.getRandomString());
        String encRandomString = alice.getEncrypted(alice.getRandomString(), alice.getSessionKey());
        System.out.printf("\tзашифровывает случайную строку Ra и получает %s\n", encRandomString);
        System.out.printf("""
                %s посылает пользователю %s следующее сообщение:
                \t- %s\n""", alice.getName(), bob.getName(), encRandomString);
        step4(encRandomString);
    }

    private void step4(String encRandomAliceString) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("\n--- Шаг 4 ---");
        String decRandomAliceString = bob.getDecrypted(encRandomAliceString, bob.getSessionKey());
        bob.generateString();
        String encBobString = bob.getEncrypted(bob.getRandomString(), bob.getSessionKey());
        String encAliceString = bob.getEncrypted(decRandomAliceString, bob.getSessionKey());
        System.out.printf("""
                %s делает следующее:
                \tрасшифровывает сообщение и получает Ra = %s
                \tгенерирует случайную строку Rb = %s
                \tзашифровывает Rb и получает %s
                \tзашифровывает Ra и получает %s\n""", bob.getName(), decRandomAliceString, bob.getRandomString(), encBobString, encAliceString);
        System.out.printf("""
                %s посылает пользователю %s следующее сообщение:
                \t- %s
                \t- %s\n""", bob.getName(), alice.getName(), encAliceString, encBobString);
        step5(encAliceString, encBobString);
    }

    private void step5(String encAliceString, String encBobString) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("\n--- Шаг 5 ---");
        String decAliceString = alice.getDecrypted(encAliceString, alice.getSessionKey());
        String decBobString = alice.getDecrypted(encBobString, alice.getSessionKey());
        System.out.printf("""
                %s расшифровывает сообщение и получает:
                \t- Ra = %s
                \t- Rb = %s\n""", alice.getName(), decAliceString, decBobString);
        if (!decAliceString.equals(alice.getRandomString())) {
            System.out.println("Полученная строка Ra отличается от изначальной. Выход из алгоритма.");
            return;
        }
        String encBobStringByAlice = alice.getEncrypted(decBobString, alice.getSessionKey());
        System.out.printf("""
                %s зашифровывает Rb и посылает пользователю %s следующее сообщение:
                \t- %s\n""", alice.getName(), bob.getName(), encBobStringByAlice);
        step6(encBobStringByAlice);
    }

    private void step6(String encBobStringByAlice) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("\n--- Шаг 6 ---");
        String decBobString = bob.getDecrypted(encBobStringByAlice, bob.getSessionKey());
        System.out.printf("""
                %s расшифровывает сообщение и получает:
                \t- Rb = %s\n""", bob.getName(), decBobString);
        if (!decBobString.equals(bob.getRandomString())) {
            System.out.println("Полученная строка Rb отличается от изначальной. Выход из алгоритма.");
            return;
        }
        System.out.printf("Протокол завершен успешно. Установлен сеансовый ключ K = %d\n\n", alice.getSessionKeyInt());
    }

    private BigInteger generatePrimitiveRoot(BigInteger n) {
        if (!n.isProbablePrime(100)) {
            throw new IllegalArgumentException("Переданное число не является простым");
        }
        SecureRandom rand = new SecureRandom();
        BigInteger prime = new BigInteger(n.bitLength(), rand).mod(n);
        ArrayList<BigInteger> orders = getDivisors(n.subtract(BigInteger.ONE));
        for (; ; ) {
            if (prime.compareTo(n) >= 0) {
                prime = BigInteger.ONE;
            }
            if (isPrimitive(prime, n, orders)) {
                return prime;
            }
            prime = prime.add(BigInteger.ONE);
        }
    }

    private boolean isPrimitive(BigInteger prime, BigInteger n, ArrayList<BigInteger> orders) {
        if (prime.compareTo(BigInteger.ONE) < 0 || prime.compareTo(n) >= 0) {
            return false;
        }
        for (BigInteger each : orders) {
            if (prime.modPow(each, n).compareTo(BigInteger.ONE) == 0) {
                if (each.compareTo(n.subtract(BigInteger.ONE)) == 0) {
                    return true;
                }
                break;
            }
        }
        return false;
    }

    private ArrayList<BigInteger> getDivisors(BigInteger num) {
        ArrayList<BigInteger> divisors = new ArrayList<>();
        for (BigInteger i = BigInteger.ONE; i.compareTo(num.divide(BigInteger.TWO).add(BigInteger.ONE)) < 0; i = i.add(BigInteger.ONE)) {
            if (num.mod(i).compareTo(BigInteger.ZERO) == 0) {
                divisors.add(i);
            }
        }
        divisors.add(num);
        return divisors;
    }
}
