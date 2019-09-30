import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.io.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;



public class Sender{
    private static int BUFFER_SIZE = 32 * 1024;
    public static String message_hash;

    public static void main(String[] args) throws Exception {
        System.out.println();
        hashValue("message.txt"); // Number 4
        RSA("message.dd"); // Number 5
    }

    public static String hashValue(String message_file) throws Exception {
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
        System.out.println("SHA256(M) in Hexadecimal bytes:");
        for (int k=0, j=0; k<hash.length; k++, j++) {
            System.out.format("%02X ", (hash[k])) ;
            // save value to message.dd file
            out.format("%02X ", (hash[k]));
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        System.out.println("");
        out.close();

        return new String(hash);
    }

    public static String RSA(String fileName) throws IOException {
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
            byte[] hash_byte = new byte[message_hash.length() / 2];
            for (int i = 0; i < hash_byte.length; i++) {
                int index = i * 2;
                int j = Integer.parseInt(message_hash.substring(index, index + 2), 16);
                hash_byte[i] = (byte)j;
            }

            for (int i = 0; i < hash_byte.length; i++) {
                System.out.format("%02X ", (hash_byte[i]));
            }
            System.out.println();

            byte[] mess_hash_bytes = message_hash.getBytes();
            //System.out.println(message_hash);
            //System.out.println(mess_hash_bytes[1]);

//            PrintWriter out2 = new PrintWriter("message.ds-msg");
//            for (int k=0, j=0; k<mess_hash_bytes.length; k++, j++) {
//                System.out.format("%2X ", (mess_hash_bytes[k])) ;
//                // save value to message.dd file
//                out2.format("%2X ", (mess_hash_bytes[k]));
//                if (j >= 15) {
//                    System.out.println("");
//                    j=-1;
//                }
//            }
            return sb.toString();
        } finally {
            br.close();
        }
    }

}
