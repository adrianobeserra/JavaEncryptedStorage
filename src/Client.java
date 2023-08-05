import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Client {


    public static void main(String[] args) {
        var host = args[0];
        var port = Integer.parseInt(args[1]);
        var userid = args[2];
        var fileName = args[3];

        try (Socket clientSocket = new Socket(host, port)) {
            System.out.println("Connected to the server.");

            Utils.sendBytes(clientSocket.getOutputStream(), userid.getBytes());
            Utils.sendBytes(clientSocket.getOutputStream(), fileName.getBytes());

            // Load the client's RSA private key
            PrivateKey privateKey = Utils.loadPrivateKey(userid);

            // Load the server's RSA public key
            PublicKey serverPublicKey = Utils.loadPublicKey("server");

            // Generate and send client's 16 fresh random bytes
            byte[] clientBytes = Utils.generateRandomBytes(16);
            byte[] encryptedClientBytes = Utils.encryptRSA(clientBytes, serverPublicKey);
            byte[] clientSignature = Utils.signData(encryptedClientBytes, privateKey);

            // Send the encrypted client bytes and the client signature to the server
            Utils.sendBytes(clientSocket.getOutputStream(), encryptedClientBytes);
            Utils.sendBytes(clientSocket.getOutputStream(), clientSignature);

            // Receive the server's 16 fresh random bytes
            byte[] encryptedServerBytes = Utils.receiveBytes(clientSocket.getInputStream());
            byte[] serverSignatureBytes = Utils.receiveBytes(clientSocket.getInputStream());

            byte[] encryptedServerData = Arrays.copyOf(encryptedServerBytes, encryptedServerBytes.length - 1);
            byte[] serverSignature = Arrays.copyOf(serverSignatureBytes, serverSignatureBytes.length - 1);

            // Verify the server signature and decrypt the server bytes
            if (Utils.verifySignature(encryptedServerData, serverSignature, serverPublicKey)) {
                byte[] serverBytes = Utils.decryptRSA(encryptedServerBytes, privateKey);

                // Concatenate the client's and server's bytes to form the AES key
                byte[] aesKeyBytes = Utils.concatenateBytes(clientBytes, serverBytes);
                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                // Encrypt and send the file content to the server
                File file = new File(fileName);
                byte[] fileContent = Utils.readFile(file);
                byte[] encryptedFileContent = Utils.encryptAES(fileContent, aesKey, clientBytes);
                Utils.sendBytes(clientSocket.getOutputStream(), encryptedFileContent);
            } else {
                System.out.println("Server signature verification failed. Terminating the connection.");
            }
            // Close the socket and finish the client
            clientSocket.close();
            System.out.println("File transfer complete. File: " + fileName);
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException |
                 InvalidKeyException | NoSuchPaddingException | BadPaddingException |
                 InvalidKeySpecException | SignatureException e) {
            System.err.println("Error: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}