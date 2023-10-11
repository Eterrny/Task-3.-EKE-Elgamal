import org.junit.Assert;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class AESServiceTest {

    @org.junit.jupiter.api.Test
    void testEncryptDecrypt() throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        AESService aes = new AESService();
        String input = "testblabla";
        SecretKey key = aes.getPublicKey();
        IvParameterSpec ivParameterSpec = AESService.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherText = AESService.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AESService.decrypt(algorithm, cipherText, key, ivParameterSpec);
        Assert.assertEquals(input, plainText);
    }

    @org.junit.jupiter.api.Test
    void testKeyConversion() throws NoSuchAlgorithmException {
        AESService aes = new AESService();
        SecretKey encodedKey = aes.getPublicKey();
        String encodedString = AESService.convertSecretKeyToString(encodedKey);
        SecretKey decodeKey = AESService.convertStringToSecretKey(encodedString);
        Assert.assertEquals(encodedKey, decodeKey);
    }
}