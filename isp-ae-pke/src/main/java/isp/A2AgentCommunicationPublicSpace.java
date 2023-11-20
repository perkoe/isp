package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationPublicSpace {
    private static final int GCM_TAG_LENGTH = 128; // in bits
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        KeyGenerator keyGenChaCha20 = KeyGenerator.getInstance("ChaCha20");
        keyGenChaCha20.init(256); // Use 256-bit key
        SecretKey chaCha20Key = keyGenChaCha20.generateKey();

        // Create an AES key that is used by Bob and the public-space
        KeyGenerator keyGenAES = KeyGenerator.getInstance("AES");
        keyGenAES.init(256); // Use 256-bit key
        SecretKey aesKey = keyGenAES.generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.

                send("bob", data);

                // Compute digest
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] digest = sha256.digest(data);

                // Encrypt digest with ChaCha20-Poly1305
                Cipher chachaCipher = Cipher.getInstance("ChaCha20-Poly1305");
                byte[] iv = new byte[12]; // ChaCha20-Poly1305 requires a 12-byte nonce
                new SecureRandom().nextBytes(iv);
                chachaCipher.init(Cipher.ENCRYPT_MODE, chaCha20Key, new IvParameterSpec(iv));
                byte[] encryptedDigest = chachaCipher.doFinal(digest);

                // Send IV and encrypted digest to public space
                send("public-space", iv);
                send("public-space", encryptedDigest);

            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                byte[] ivFromAlice = receive("alice");
                byte[] encryptedDigestFromAlice = receive("alice");
                Cipher chachaCipher = Cipher.getInstance("ChaCha20-Poly1305");
                chachaCipher.init(Cipher.DECRYPT_MODE, chaCha20Key, new IvParameterSpec(ivFromAlice));
                byte[] decryptedDigest = chachaCipher.doFinal(encryptedDigestFromAlice);

                // Encrypt the digest with AES-GCM
                Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
                byte[] iv = new byte[12]; // GCM recommended IV length is 12 bytes
                new SecureRandom().nextBytes(iv);
                GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
                byte[] encryptedDigestForBob = aesCipher.doFinal(decryptedDigest);

                // Send encrypted digest and IV to Bob
                send("bob", iv);
                send("bob", encryptedDigestForBob);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                byte[] dataFromAlice = receive("alice");
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] computedDigest = sha256.digest(dataFromAlice);

                // Receive encrypted digest and IV from Public Space
                byte[] iv = receive("public-space");
                byte[] encryptedDigest = receive("public-space");

                // Decrypt the digest
                Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
                byte[] decryptedDigest = aesCipher.doFinal(encryptedDigest);

                // Compare digests
                if (Arrays.equals(computedDigest, decryptedDigest)) {
                    System.out.println("data valid");
                } else {
                    System.out.println("data invalid");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
