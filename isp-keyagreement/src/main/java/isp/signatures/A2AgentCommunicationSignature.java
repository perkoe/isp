package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();
        final String signingAlgorithm = "SHA256withECDSA";

        // Create key pairs
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        final KeyPair aliceKeyPair = keyGen.generateKeyPair();
        final KeyPair bobKeyPair = keyGen.generateKeyPair();




        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signarure pair, verify the signature
                // repeat 10 times
                Signature aliceSignature = Signature.getInstance(signingAlgorithm);
                for (int i = 0; i < 10; i++) {
                    final String message = "We would like to sign this " + i;
                    aliceSignature.initSign(aliceKeyPair.getPrivate());
                    aliceSignature.update(message.getBytes());
                    final byte[] signedMessage = aliceSignature.sign();

                    System.out.println("Signature: " + Agent.hex(signedMessage));

                    // Send message and signature to Bob
                    send("bob", message.getBytes());
                    send("bob", signedMessage);

                    // Receive message and signature from Bob
                    final byte[] receivedMessage = receive("bob");
                    final byte[] receivedSignature = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(bobKeyPair.getPublic());
                    verifier.update(receivedMessage);

                    if (verifier.verify(receivedSignature)) {
                        System.out.println("Valid signature.");
                    } else {
                        System.err.println("Invalid signature.");
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                Signature bobSignature = Signature.getInstance(signingAlgorithm);
                for (int i = 0; i < 10; i++) {
                    // Receive message and signature from Alice
                    final byte[] receivedMessage = receive("alice");
                    final byte[] receivedSignature = receive("alice");

                    // Verify Alice's signature
                    final Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(aliceKeyPair.getPublic()); // Assuming Bob knows Alice's public key
                    verifier.update(receivedMessage);


                    if (verifier.verify(receivedSignature)) {
                        System.out.println("Alice's signature is valid.");
                    } else {
                        System.err.println("Alice's signature is invalid.");
                    }


                    // Respond back to Alice
                    String responseMessage = "Response " + i;
                    bobSignature.initSign(bobKeyPair.getPrivate());
                    bobSignature.update(responseMessage.getBytes(StandardCharsets.UTF_8));
                    final byte[] responseSignature = bobSignature.sign();

                    System.out.println("Bob's Signature: " + Agent.hex(responseSignature));


                    send("alice", responseMessage.getBytes());
                    send("alice", responseSignature);
                }
                }
        });

        env.connect("alice", "bob");
        env.start();
    }
}