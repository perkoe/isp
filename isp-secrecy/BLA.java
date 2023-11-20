public class BLA {
}
    key agreement: 4. vaje

        SIGNATURE:

        package isp.signatures;


        import fri.isp.Agent;


        import java.nio.charset.StandardCharsets;
        import java.security.KeyPair;
        import java.security.KeyPairGenerator;
        import java.security.Signature;


public class SignatureExample {
    public static void main(String[] args) throws Exception {


        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
        final String signingAlgorithm =
                "SHA256withRSA";
//         "SHA256withDSA";
//        "SHA256withECDSA";
        final String keyAlgorithm =
                "RSA";
//         "DSA";
//         "EC";




        // The message we want to sign
        final String document = "We would like to sign this.";


        /*
         * STEP 1.
         * We create a public-private key pair using standard algorithm names
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final KeyPair key = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();


        /*
         * Alice creates Signature object defining Signature algorithm.
         */
        final Signature signer = Signature.getInstance(signingAlgorithm);


        /*
         * We initialize the signature object with
         * - Operation modes (SIGN) and
         * - provides appropriate ***Private*** Key
         */
        signer.initSign(key.getPrivate());


        // Finally, we load the document into the signature object and sign it
        signer.update(document.getBytes(StandardCharsets.UTF_8));
        final byte[] signature = signer.sign();
        System.out.println("Signature: " + Agent.hex(signature));


        /*
         * To verify the signature, we create another signature object
         * and specify its algorithm
         */
        final Signature verifier = Signature.getInstance(signingAlgorithm);


        /*
         * We have to initialize in the verification mode. We only need
         * to know public key of the signer.
         */
        verifier.initVerify(key.getPublic());


        // Check whether the signature is valid
        verifier.update(document.getBytes(StandardCharsets.UTF_8));


        if (verifier.verify(signature))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}

    Key derivation:
        package isp.signatures;


        import fri.isp.Agent;


        import javax.crypto.Mac;
        import javax.crypto.SecretKey;
        import javax.crypto.SecretKeyFactory;
        import javax.crypto.spec.PBEKeySpec;
        import javax.crypto.spec.SecretKeySpec;
        import java.nio.charset.StandardCharsets;
        import java.security.spec.KeySpec;


public class KeyDerivation {
    public static void main(String[] args) throws Exception {
        // password from which the key will be derived
        final String password = "hunter2";


        // a random, public and fixed string
        final byte[] salt = "89fjh3409fdj390fk".getBytes(StandardCharsets.UTF_8);


        // use PBKDF2 with the password, salt, and number of iterations and required bits
        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt,
                10000, 128);
        final SecretKey generatedKey = pbkdf.generateSecret(specs);


        System.out.printf("key = %s%n", Agent.hex(generatedKey.getEncoded()));
        System.out.printf("len(key) = %d bytes%n", generatedKey.getEncoded().length);


        final String message = "Hello World!";


        // for example, use the derived key as the HMAC key
        final Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
        System.out.printf("HMAC[%s] = %s%n", message, Agent.hex(hmac.doFinal(message.getBytes())));


    }
}

komunikacija:
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
    public static void main(String[] args) throws   NoSuchAlgorithmException {
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


                    System.out.println("Signature:"+Agent.hex(signedMessage));


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
                    //  message and signature from Alice
                    final byte[] receivedMessage = receive("alice");
                    final byte[] receivedSignature = receive("alice");


                    // Verify Alice's signature
                    final Signature verifier Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(aliceKeyPair.getPublic());
//     Assuming Bob knows Alice's public key
                    verifier.update(receivedMessage);




                    if (verifier.verify(receivedSignature)) {
                        System.out.println("Alice's signature is valid.");
                    } else {
                        ystem.err.println("Alice's signature is invalid.");
                    }




                    // Respond back to Alice
                    String responseMessage = "Response " + i;
                    bobSignature.initSign(bobKeyPair.getPrivate());
                    bobSignature.update(responseMessage.getBytes(StandardCharsets.UTF_8));
                    final byte[] responseSignature = bobSignature.sign();


                    System.out.println("Bob's Signature:"+Agent.hex(responseSignature));




                    send("alice", responseMessage.getBytes());
                    send("alice", responseSignature);
                }
            }
        });


        env.connect("alice", "bob");
        env.start();
    }
}

































3 vaje-
        RSA
        package isp;


        import fri.isp.Agent;


        import javax.crypto.Cipher;
        import java.nio.charset.StandardCharsets;
        import java.security.KeyPair;
        import java.security.KeyPairGenerator;


/**
 * Assignments:
 * - Find out how to manually change the RSA modulus size
 * - Set padding to NoPadding. Encrypt a message and decrypt it. Is the
 * decrypted text the same as the original plaint text? Why?
 */
public class RSAExample {


    public static void main(String[] args) throws Exception {
        // Set RSA cipher specs:
        //  - Set mode to ECB: each block is encrypted independently
        //  - Set padding to OAEP (preferred mode);
        //    alternatives are PKCS1Padding (the default) and NoPadding ("textbook" RSA)
        final String algorithm = "RSA/ECB/OAEPPadding";
        final String message = "I would like to keep this text confidential, Bob. Kind regards, Alice.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);


        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));


        // STEP 1: Bob creates his public and private key pair.
        // Alice receives Bob's public key.
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKP = kpg.generateKeyPair();


        // STEP 2: Alice creates Cipher object defining cipher algorithm.
        // She then encrypts the clear-text and sends it to Bob.
        final Cipher rsaEnc = Cipher.getInstance(algorithm);
        rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
        final byte[] ct = rsaEnc.doFinal(pt);


        // STEP 3: Display cipher text in hex. This is what an attacker would see,
        // if she intercepted the message.
        System.out.println("CT: " + Agent.hex(ct));


        // STEP 4: Bob decrypts the cipher text using the same algorithm and his private key.
        final Cipher rsaDec = Cipher.getInstance(algorithm);
        rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        final byte[] decryptedText = rsaDec.doFinal(ct);


        // STEP 5: Bob displays the clear text
        System.out.println("PT: " + Agent.hex(decryptedText));
        final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println("Message: " + message2);
    }
}

GCM:

        package isp;


        import fri.isp.Agent;


        import javax.crypto.Cipher;
        import javax.crypto.KeyGenerator;
        import javax.crypto.SecretKey;
        import javax.crypto.spec.GCMParameterSpec;
        import java.nio.charset.StandardCharsets;


/**
 * An example of using the authenticated encryption cipher.
 * <p>
 * During the encryption, the Galois-Counter mode automatically
 * creates a MAC and verifies it during the decryption.
 * <p>
 * What happens, if the cipher text gets modified?
 * What happens, if the IV gets modified?
 * What happens, if the key is incorrect?
 */
public class GCMExample {
    public static void main(String[] args) throws Exception {
        // shared key
        final SecretKey sharedKey = KeyGenerator.getInstance("AES").generateKey();


        // the payload
        final String message = "this is my message";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        System.out.printf("MSG: %s%n", message);
        System.out.printf("PT:  %s%n", Agent.hex(pt));


        // encrypt
        final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
        alice.init(Cipher.ENCRYPT_MODE, sharedKey);
        final byte[] ct = alice.doFinal(pt);
        System.out.printf("CT:  %s%n", Agent.hex(ct));


        // send IV
        final byte[] iv = alice.getIV();
        System.out.printf("IV:  %s%n", Agent.hex(iv));


        // decrypt
        final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
        // the length of the MAC tag is either 128, 120, 112, 104 or 96 bits
        // the default is 128 bits
        final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
        bob.init(Cipher.DECRYPT_MODE, sharedKey, specs);
        final byte[] pt2 = bob.doFinal(ct);
        System.out.printf("PT:  %s%n", Agent.hex(pt2));
        System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));
    }
}

    USING GCM

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


    using PublicSpace:

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


    using RSA:

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

vaje 2: INTEGRITY
        message digest

        package isp.integrity;


        import fri.isp.Agent;


        import java.nio.charset.StandardCharsets;
        import java.security.MessageDigest;
        import java.security.NoSuchAlgorithmException;


public class MessageDigestExample {


    public static void main(String[] args) throws NoSuchAlgorithmException {


        final String message = "We would like to provide data integrity.";


        /*
         * STEP 1.
         * Select Message Digest algorithm and get new Message Digest object instance
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");


        /*
         * STEP 2.
         * Create new hash using message digest object.
         */
        final byte[] hashed = digestAlgorithm.digest(message.getBytes(StandardCharsets.UTF_8));


        /*
         * STEP 4: Print out hash. Note we have to convert a byte array into
         * hexadecimal string representation.
         */
        final String hashAsHex = Agent.hex(hashed);
        System.out.println(hashAsHex);
    }
}


    HMAC example:

        package isp.integrity;


        import fri.isp.Agent;


        import javax.crypto.KeyGenerator;
        import javax.crypto.Mac;
        import java.nio.charset.StandardCharsets;
        import java.security.InvalidKeyException;
        import java.security.Key;
        import java.security.MessageDigest;
        import java.security.NoSuchAlgorithmException;
        import java.util.Arrays;


public class HMACExample {
    public static void main(String[] args) throws Exception {


        final String message = "We would like to provide data integrity for this message.";


        /*
         * STEP 1.
         * Select HMAC algorithm and get new HMAC object instance.
         * Standard Algorithm Names
         * http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
         */
        final Mac alice = Mac.getInstance("HmacSHA256");


        /*
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();


        /*
         * STEP 3.
         * Initialize HMAC and provide shared secret session key. Create an HMAC tag.
         */
        alice.init(key);
        final byte[] tag1 = alice.doFinal(message.getBytes(StandardCharsets.UTF_8));


        /*
         * STEP 4.
         * Print out HMAC.
         */
        final String messageHmacAsString = Agent.hex(tag1);
        System.out.println("HMAC: " + messageHmacAsString);


        /*
         * STEP 5.
         * Bob verifies the tag.
         */
        final Mac bob = Mac.getInstance("HmacSHA256");
        bob.init(key);
        final byte[] tag2 = bob.doFinal(message.getBytes(StandardCharsets.UTF_8));


        // Is the mac correct?


        // Never compare MACs this way
        System.out.println(verify1(tag1, tag2));


        // Better
        System.out.println(verify2(tag1, tag2));


        // Even better
        System.out.println(verify3(tag1, tag2, key));


        // The best
        System.out.println(MessageDigest.isEqual(tag1, tag2));
    }


    public static boolean verify1(byte[] tag1, byte[] tag2) {
       /*
           FIXME: This is insecure
           - The comparison is done byte by byte
           - The comparator returns false immediately after the first inequality of bytes is found
           (Use CTRL+click and see how the  Arrays.equals() is implemented)
        */
        return Arrays.equals(tag1, tag2);
    }


    public static boolean verify2(byte[] tag1, byte[] tag2) {
       /*
           FIXME: Defense #1


           The idea is to compare all bytes


           Important: A "smart" compiler may try to optimize this code
           and end the loop prematurely and thus work against you ...
        */


        if (tag1 == tag2)
            return true;
        if (tag1 == null || tag2 == null)
            return false;


        int length = tag1.length;
        if (tag2.length != length)
            return false;


        // This loop never terminates prematurely
        byte result = 0;
        for (int i = 0; i < length; i++) {
            result |= tag1[i] ^ tag2[i];
        }
        return result == 0;
    }


    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
       /*
           FIXME: Defense #2


           The idea is to hide which bytes are actually being compared
           by MAC-ing the tags once more and then comparing those tags
        */
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);


        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);


        return Arrays.equals(tagtag1, tagtag2);
    }


}

    hmac talk:
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

vaje1- secrecy

        package isp.secrecy;


        import fri.isp.Agent;


        import javax.crypto.Cipher;
        import javax.crypto.KeyGenerator;
        import java.security.Key;


/**
 * EXERCISE:
 * - Study the example
 * - Test different ciphers
 *
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class SymmetricCipherExample {
    public static void main(String[] args) throws Exception {
        final String message = "Hi Bob, this is Alice.";
        System.out.println("[MESSAGE] " + message);


        // STEP 1: Alice and Bob agree upon a cipher and a shared secret key
        final Key key = KeyGenerator.getInstance("RC4").generateKey();


        final byte[] pt = message.getBytes();
        System.out.println("[PT] " + Agent.hex(pt));


        //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
        final Cipher encrypt = Cipher.getInstance("RC4");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);


        // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
        System.out.println("[CT] " + Agent.hex(cipherText));


        /*
         * STEP 4.
         * The receiver creates a Cipher object, defines the algorithm, the secret key and
         * possibly additional parameters (such as IV), and then decrypts the cipher text
         */
        final Cipher decrypt = Cipher.getInstance("RC4");
        decrypt.init(Cipher.DECRYPT_MODE, key);
        final byte[] dt = decrypt.doFinal(cipherText);
        System.out.println("[PT] " + Agent.hex(dt));


        // Todo: What happens if the key is incorrect? (Try with RC4 or AES in CTR mode)


        // STEP 5: Create a string from a byte array
        System.out.println("[MESSAGE] " + new String(dt));
    }
}


    agent communication
package isp.secrecy;


        import fri.isp.Agent;
        import fri.isp.Environment;


/**
 * A communication channel is implemented with thread-safe blocking queue.
 * <p/>
 * Both agents are implemented by extending the Agents class,
 * creating anonymous class and overriding #execute().
 * <p/>
 * Both agents are started at the end of the main method definition below.
 */
public class AgentCommunication {
    public static void main(String[] args) {
        final Environment env = new Environment();


        env.add(new Agent("alice") {
            @Override
            public void task() {
                final byte[] payload = "Hi, Bob, this is Alice.".getBytes();
                send("bob", payload);
                final byte[] received = receive("bob");
                print("Got '%s', converted to string: '%s'", hex(received), new String(received));
            }
        });


        env.add(new Agent("bob") {
            @Override
            public void task() {
                send("alice", "Hey Alice, Bob here.".getBytes());
                print("Got '%s'", new String(receive("alice")));
            }
        });


        env.connect("alice", "bob");
        env.start();
    }
}

    exhaustive search:

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

chacha:

        package isp.secrecy;


        import fri.isp.Agent;
        import fri.isp.Environment;


        import javax.crypto.Cipher;
        import javax.crypto.KeyGenerator;
        import javax.crypto.spec.ChaCha20ParameterSpec;
        import java.security.Key;
        import java.security.SecureRandom;


/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();


        // STEP 2: Setup communication
        final Environment env = new Environment();


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */
                final SecureRandom random = new SecureRandom();
                for (int i = 0; i < 10; i++) {
                    byte[] nonce = new byte[12];  // ChaCha20 uses a 12-byte nonce
                    random.nextBytes(nonce);


                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1));
                    final byte[] cipherText = encrypt.doFinal(message.getBytes());


                    send("bob", nonce);
                    send("bob", cipherText);
                }
            }
        });


        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // TODO
                for (int i = 0; i < 10; i++) {
                    final byte[] nonce = receive("alice");
                    final byte[] cipherText = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1));
                    final byte[] plainText = decrypt.doFinal(cipherText);
                    print("Received: '%s'", new String(plainText));
                }
            }
        });




        env.connect("alice", "bob");
        env.start();
    }
}


    CTR MODE:

        package isp.secrecy;


        import fri.isp.Agent;
        import fri.isp.Environment;


        import javax.crypto.Cipher;
        import javax.crypto.KeyGenerator;
        import javax.crypto.spec.IvParameterSpec;
        import java.security.Key;


/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();


        // STEP 2: Setup communication
        final Environment env = new Environment();


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
                for (int i = 0; i < 10; i++) {
                    final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(message.getBytes());
                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);
                    send("bob", cipherText);
                }
            }
        });


        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */
                for (int i = 0; i < 10; i++) {
                    final byte[] iv = receive("alice");
                    final byte[] cipherText = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    final byte[] plainText = decrypt.doFinal(cipherText);
                    print("Received: '%s'", new String(plainText));
                }
            }
        });


        env.connect("alice", "bob");
        env.start();
    }
}

    CBC mode:

        package isp.secrecy;


        import fri.isp.Agent;
        import fri.isp.Environment;


        import javax.crypto.Cipher;
        import javax.crypto.KeyGenerator;
        import javax.crypto.spec.IvParameterSpec;
        import java.security.Key;


/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();


        // STEP 2: Setup communication
        final Environment env = new Environment();




        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                //final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
                for (int i = 0; i < 10; i++) {
                    final String message = "I love you Bob. Kisses, Alice.";
                    final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(message.getBytes());
                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);
                    send("bob", cipherText);
                }
            }
        });


        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */
                for (int i = 0; i < 10; i++) {
                    final byte[] iv = receive("alice");
                    final byte[] cipherText = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    final byte[] plainText = decrypt.doFinal(cipherText);
                    print("Received: '%s'", new String(plainText));
                }
            }
        });


        env.connect("alice", "bob");
        env.start();
    }
}

