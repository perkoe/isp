package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        //final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // Get Bob's public key
                PublicKey bobPublicKey = bobKP.getPublic();
                /*
                - Create an RSA cipher and encrypt a message using Bob's PK
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, bobPublicKey);

                String message = "Hello Bob!";
                byte[] encryptedBytes = cipher.doFinal(message.getBytes());
                //String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
                send("bob", encryptedBytes);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                PrivateKey bobPrivateKey = bobKP.getPrivate();
                byte[] incoming = receive("alice");
                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                // Create an RSA cipher
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, bobPrivateKey);

                // Decrypt incoming ciphertext using Bob's private key
                byte[] decryptedBytes = cipher.doFinal(incoming);
                String decryptedMessage = new String(decryptedBytes);

                // Print the decrypted message
                System.out.println("Decrypted message: " + decryptedMessage);

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
