package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;

public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        final Environment env = new Environment();


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I hope you get this message intact. Kisses, Alice";
                final Mac alice = Mac.getInstance("HmacSHA256");
                alice.init(key);
                // Print the key for Alice
                System.out.println("Alice's Key: " + Agent.hex(key.getEncoded()));

                final byte[] tag1 = alice.doFinal(message.getBytes(StandardCharsets.UTF_8));
                System.out.println("HMAC from Alice: " + Agent.hex(tag1));

                send("bob", message.getBytes(StandardCharsets.UTF_8)); // Send the message
                send("bob", tag1); // Send the HMAC separately
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] receivedMessage = receive("alice");
                final byte[] receivedHMAC = receive("alice");

                final Mac bob = Mac.getInstance("HmacSHA256");
                bob.init(key);
                System.out.println("Bob's Key: " + Agent.hex(key.getEncoded()));

                byte[] tag2 = bob.doFinal(receivedMessage);
                System.out.println("HMAC from Bob: " + Agent.hex(tag2));

                System.out.println(MessageDigest.isEqual(receivedHMAC, tag2));
            }
        });


        env.connect("alice", "bob");
        env.start();
    }
}
