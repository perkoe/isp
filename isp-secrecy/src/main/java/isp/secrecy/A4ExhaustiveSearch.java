package isp.secrecy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;

public class A4ExhaustiveSearch {

    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        byte[] sampleKey = new byte[]{0, 0, 0, 0, 0, 15, 4, 65}; // Sample key.
        byte[] ct = encryptWithKey(message, sampleKey);
        System.out.println("secret key " + arrayToString(sampleKey));

        List<byte[]> matchingKeys = bruteForceKey(ct, message);
        System.out.println("Matching keys:");
        for (byte[] key : matchingKeys) {
            System.out.println(arrayToString(key));
        }
    }

    public static byte[] encryptWithKey(String message, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message.getBytes());
    }

    public static List<byte[]> bruteForceKey(byte[] ct, String message) throws Exception {
        List<byte[]> matchingKeys = new ArrayList<>();

        for (int i = Byte.MIN_VALUE; i <= Byte.MAX_VALUE; i++) {
            for (int j = Byte.MIN_VALUE; j <= Byte.MAX_VALUE; j++) {
                for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++) {
                    byte[] potentialKey = new byte[]{0, 0, 0, 0, 0, (byte) i, (byte) j, (byte) k};
                    try {
                        SecretKeySpec secretKey = new SecretKeySpec(potentialKey, "DES");
                        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                        cipher.init(Cipher.DECRYPT_MODE, secretKey);
                        byte[] decryptedMessageBytes = cipher.doFinal(ct);

                        if (new String(decryptedMessageBytes).equals(message)) {
                            matchingKeys.add(potentialKey);
                        }
                    } catch (javax.crypto.BadPaddingException e) {
                        // This will occur frequently when the key is incorrect. Just ignore it.
                    }
                }
            }
        }
        return matchingKeys;
    }

    private static String arrayToString(byte[] bytes) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < bytes.length; i++) {
            sb.append(bytes[i]);
            if (i < bytes.length - 1) {
                sb.append(", ");
            }
        }
        sb.append("]");
        return sb.toString();
    }
}
