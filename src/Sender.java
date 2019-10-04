import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;


public class Sender{
    private static int BUFFER_SIZE = 32 * 1024;
    public static String message_hash;
    public static byte[] hash_byte;
    public static String symmetricKey;
    public static String ds_msg;
    public static PrivateKey XprivKey2;
    public static byte[] symmetricBytes;

    public static void main(String[] args) throws Exception {

        // **** SHA/RSA ****
        sha_256("message.txt");
        // Number 5, String from message.dd to byte[] for RSA/Kx- Encryption
        string_to_byte("message.dd");
        // Number 5, RSA Encryption using Kx- Key.
        rsa_encrypt();

        // **** AES ****
        key_to_UTF8("symmetric.key");
        read_ds_msg("message.ds-msg");
        aes_encrypt();

    }

    public static String sha_256(String message_file) throws Exception {

        BufferedInputStream file = new BufferedInputStream(new FileInputStream(message_file));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, md);
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            i = in.read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        md = in.getMessageDigest();
        in.close();

        byte[] hash = md.digest();
        PrintWriter out = new PrintWriter("message.dd");
        System.out.println("SHA256(M) in Hexadecimal bytes, output to message.dd:");
        for (int k = 0, j = 0; k < hash.length; k++, j++) {
            System.out.format("%02X ", (hash[k])) ;
            // save value to message.dd file
            out.format("%02X ", (hash[k]));
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
        System.out.println("");
        out.close();

        return new String(hash);
    }

    public static String string_to_byte(String fileName) throws IOException {

        BufferedReader br = new BufferedReader(new FileReader(fileName));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = br.readLine();
            }

            message_hash = sb.toString();
            message_hash = message_hash.replaceAll("\\s+","");

            // Convert Hex String to byte Array.
            hash_byte = new byte[message_hash.length() / 2];
            for (int i = 0; i < hash_byte.length; i++) {
                int index = i * 2;
                int j = Integer.parseInt(message_hash.substring(index, index + 2), 16);
                hash_byte[i] = (byte)j;
            }

            System.out.println("byte[] hash_byte: (Read message.dd as a string and store as byte[].) ");
            for (int i = 0; i < hash_byte.length; i++) {
                System.out.format("%02X ", (hash_byte[i]));
            }
            System.out.println();
            System.out.println();

            return sb.toString();
        } finally {
            br.close();
        }
    }

    //read key parameters from a file and generate the private key
    public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException {

        InputStream in =
                new FileInputStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }

    public static String key_to_UTF8(String fileName) throws IOException {
        System.out.println("Symmetric.key string for AES En(): ");
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = br.readLine();
            }
            symmetricKey = sb.toString();
            System.out.print(symmetricKey);
            return sb.toString();
        } finally {
            br.close();
            System.out.println("128-bit UTF-8 encoding of Symmetric.key for AES: ");
            symmetricBytes = symmetricKey.getBytes("UTF-8");
            symmetricBytes = trim(symmetricBytes);
            for (byte x: symmetricBytes) {
                System.out.print(x + " ");
            }
            System.out.println("\n");
        }
    }

    public static byte[] aes_encrypt() throws Exception {

        String IV = "AAAAAAAAAAAAAAAA"; // do not need for AES/ECB/PKCS5Padding mode
        //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symmetricBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
        PrintWriter aes_out = new PrintWriter("message.aescipher");
        byte[] AEScipher = cipher.doFinal(ds_msg.getBytes("UTF-8"));
        System.out.print("AEScipher:  \n");
        for (int i = 0, j = 0; i < AEScipher.length; i++, j++) {
            System.out.format("%02X ", AEScipher[i]);
            aes_out.format("%02X ", AEScipher[i]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
        System.out.println();
        aes_out.close();
        return cipher.doFinal(ds_msg.getBytes("UTF-8"));
    }

    public static byte[] rsa_encrypt() throws Exception {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        SecureRandom Xrandom = new SecureRandom();
        XprivKey2 = readPrivKeyFromFile("XPrivate.key");
        cipher.init(Cipher.ENCRYPT_MODE, XprivKey2, Xrandom);
        PrintWriter out = new PrintWriter("message.ds-msg");
        byte[] cipherText = cipher.doFinal(hash_byte);
        System.out.println("RSA Encryption cipherText: block size = " + cipher.getBlockSize());
        for (int i = 0, j = 0; i < cipherText.length; i++, j++) {
            System.out.format("%02X ", (cipherText[i]));
            out.format("%02X ", (cipherText[i]));
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
        // read from the original message message.txt and append to message.ds-msg
        try(BufferedReader br = new BufferedReader(new FileReader("message.txt"))) {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String orig_message = sb.toString();
            out.print(orig_message);
        }
        System.out.println("");
        out.close(); // IT WONT SEND THE DATA WITHOUT THIS LINE

        return cipher.doFinal(hash_byte);
    }

    public static String read_ds_msg(String fileName) throws IOException {

        System.out.println("Read (RSA Cipertext || Message) string from message.ds-msg for AES Encryption: ");
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = br.readLine();
            }
            ds_msg = sb.toString();
            System.out.println(ds_msg);
            return sb.toString();
        } finally {
            br.close();
        }
    }

    //read key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {

        InputStream in =
                //Sender.class.getResourceAsStream(keyFileName);
                new FileInputStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }

    static byte[] trim(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
        {
            --i;
        }
        return Arrays.copyOf(bytes, i );
    }
}
