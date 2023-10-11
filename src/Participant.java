import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class Participant {
    private final String name;
    private final BigInteger p, g;
    private BigInteger y, privateElGamalKey;

    private AESService service;
    private BigInteger sessionKeyInt;
    private SecretKey sessionKey;
    private final String algorithm = "AES/CBC/PKCS5Padding";
    private String randomString;
//    private KeyHash keyHash;


    public String getName() {
        return name;
    }

    public BigInteger getY() {
        return y;
    }

    public AESService getService() {
        return service;
    }

    public BigInteger getPrivateElGamalKey() {
        return privateElGamalKey;
    }

    public BigInteger getSessionKeyInt() {
        return sessionKeyInt;
    }

    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public String getRandomString() {
        return randomString;
    }

    //    public KeyHash getKeyHash() {
//        return keyHash;
//    }

    public void generateSessionKey(BigInteger p) {
        SecureRandom rnd = new SecureRandom();
        do {
            this.sessionKeyInt = new BigInteger(p.bitLength(), rnd).mod(p);
        } while (this.sessionKeyInt.equals(BigInteger.ZERO));
        setSessionKey(this.sessionKeyInt);
//        keyHash = new KeyHash(sessionKey);
    }

    public void setSessionKey(BigInteger sessionKeyInt) {
        if (this.sessionKeyInt == null) {
            this.sessionKeyInt = sessionKeyInt;
        }
        byte[] bytesEncoded = Base64.getEncoder().encode(String.valueOf(sessionKeyInt).getBytes());
        byte[] keyBytes = new byte[16];
        System.arraycopy(bytesEncoded, 0, keyBytes, 0, bytesEncoded.length);
        this.sessionKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    public Participant(String name, BigInteger p, BigInteger g, AESService service) {
        this.name = name;
        this.service = service;
        this.p = p;
        this.g = g;
        this.setRandomPrivateKey();
        this.y = this.g.modPow(privateElGamalKey, this.p);
    }

    private void setRandomPrivateKey() {
        Random rand = new Random();
        do {
            this.privateElGamalKey = new BigInteger(this.p.bitLength(), rand).mod(p);
        } while (this.privateElGamalKey.compareTo(BigInteger.ONE) <= 0
                || this.privateElGamalKey.compareTo(p.subtract(BigInteger.ONE)) >= 0);
    }

    public String getEncrypted(String info, SecretKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return AESService.encrypt(algorithm, info, key, this.service.getIv());
    }

    public String getDecrypted(String encInfo, SecretKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return AESService.decrypt(algorithm, encInfo, key, this.service.getIv());
    }

    public void generateString() {
        int leftLimit = 48; // цифра '0'
        int rightLimit = 122; // буква 'z'
        int targetStringLength = 10;
        Random random = new Random();
        this.randomString = random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

//    public class KeyHash {
//        private BigInteger keyBigInt;
//        private String keyString;
//
//        public BigInteger getKeyBigInt() {
//            return keyBigInt;
//        }
//
//        public String getKeyString() {
//            return keyString;
//        }
//
//        public KeyHash(SecretKey key){
//            this.keyString = AESService.convertSecretKeyToString(key);
//            this.keyBigInt = new BigInteger(String.valueOf(keyString.hashCode()));
//        }
//    }
}