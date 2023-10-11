import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import static org.junit.jupiter.api.Assertions.*;

class EKEServiceTest {
    @org.junit.jupiter.api.Test
    void testService() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        EKEService service = new EKEService(new BigInteger("1021"));
        assertEquals(service.getAlice().getSessionKey(), service.getBob().getSessionKey());
    }

    @org.junit.jupiter.api.Test
    void testServiceNegative() {
        java.lang.IllegalArgumentException thrown = assertThrows(
                java.lang.IllegalArgumentException.class,
                () -> new EKEService(new BigInteger("1024")),
                "Ожидалось исключение в new EKEService(1021), но его не было."
        );
        assertEquals("Переданное число не является простым", thrown.getMessage());
    }
}