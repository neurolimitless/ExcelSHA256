import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Security;

public class CipherProcessor {


    protected CipherProcessor() {

    }

    public static void main(String[] args) {
        System.out.println(asciiToHex("16symbolpassword"));
    }


    public static String asciiToHex(String ascii) {
        return String.format("%x", new BigInteger(1, ascii.getBytes())).toUpperCase();
    }

    public static String processSalt(String salt, int length) {
        int difference = length - salt.length(); //how much times we need to add FF
        StringBuilder processedSalt = new StringBuilder(asciiToHex(salt));
        if (difference > 0) {
            for (int i = 0; i < difference; i++) {
                processedSalt.append("FF");
            }
        }
        return processedSalt.toString();
    }

    /**
     * @param key  - ASCII, must be 16-length
     * @param text - ASCII
     * @param iv   - HEX, must be 16-length
     */

    public static String AES256(String key, String text, String iv) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Hex.decodeHex(iv.toCharArray()));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
            return Hex.encodeHexString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * @param text - must be HEX
     * @param salt - must be HEX
     */
    public static String hmacSHA256(String text, String salt, int iterations) {
        try {
            String processedText = text.replace(" ", "");
            String processedSalt = salt.replace(" ", "");
            Security.addProvider(new BouncyCastleProvider());
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(processedSalt.getBytes("UTF-8"), "HmacSHA256");  //substring(12) for DGI0701
            sha256_HMAC.init(secret_key);
            byte[] result = sha256_HMAC.doFinal(processedText.getBytes("UTF-8"));
//            String result = Hex.encodeHexString(sha256_HMAC.doFinal(text.getBytes("UTF-8"),iterations)).toUpperCase(); //first iteration
            for (int i = 1; i < iterations; i++) {
                result = sha256_HMAC.doFinal(result);
            }
            return Hex.encodeHexString(result);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

}
