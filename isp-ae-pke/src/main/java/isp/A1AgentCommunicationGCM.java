package isp;
import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();
        final SecureRandom random = new SecureRandom();
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                for (int i = 1; i <= 10; i++) {
                    byte[] iv = new byte[12];
                    random.nextBytes(iv);
                    GCMParameterSpec spec = new GCMParameterSpec(128, iv);

                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
                    final byte[] ct = cipher.doFinal(pt);

                    byte[] message = new byte[iv.length + ct.length];
                    System.arraycopy(iv, 0, message, 0, iv.length);
                    System.arraycopy(ct, 0, message, iv.length, ct.length);

                    send("bob", message);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                while (true) {
                    byte[] message = receive("alice");

                    // Extract IV and ciphertext
                    byte[] iv = new byte[12];
                    System.arraycopy(message, 0, iv, 0, 12);
                    byte[] ct = new byte[message.length - 12];
                    System.arraycopy(message, 12, ct, 0, ct.length);

                    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                    cipher.init(Cipher.DECRYPT_MODE, key, spec);

                    byte[] pt = cipher.doFinal(ct);
                    System.out.println("Bob received: " + new String(pt, StandardCharsets.UTF_8));

                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
