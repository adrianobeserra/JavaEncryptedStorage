import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Server {

    public static void main(String[] args) {

        var port = Integer.parseInt(args[0]);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected");

                // Load the server's RSA private key
                PrivateKey serverPrivateKey = Utils.loadPrivateKey("server");

                // Accept and process the client's connection
                processClientConnection(clientSocket, serverPrivateKey);
            }
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException |
                 InvalidKeyException | NoSuchPaddingException | BadPaddingException |
                 InvalidKeySpecException | SignatureException e) {
            System.err.println("Error: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Client's connection
    private static void processClientConnection(Socket clientSocket, PrivateKey serverPrivateKey) throws Exception {

        //Receive the UserId and the FileName from the Client
        var userid =  new String(Utils.receiveBytes(clientSocket.getInputStream()), StandardCharsets.UTF_8).replace("\n", "");
        var fileName = new String(Utils.receiveBytes(clientSocket.getInputStream()), StandardCharsets.UTF_8).replace("\n", "");

        // Receive the client's 16 fresh random bytes
        byte[] encryptedClientBytes = Utils.receiveBytes(clientSocket.getInputStream());
        byte[] clientSignatureBytes = Utils.receiveBytes(clientSocket.getInputStream());

        //Remove delimiter byte
        byte[] encryptedClient = Arrays.copyOf(encryptedClientBytes, encryptedClientBytes.length - 1);
        byte[] clientSignature = Arrays.copyOf(clientSignatureBytes, clientSignatureBytes.length - 1);

        var clientPublicKey = Utils.loadPublicKey(userid);

        // Verify the client signature and decrypt the client bytes
        if (Utils.verifySignature(encryptedClient, clientSignature, clientPublicKey)) {
            System.out.println("Verified User ID: " + userid);

            byte[] clientBytes = Utils.decryptRSA(encryptedClient, serverPrivateKey);
            System.out.println("Client Bytes: " + Arrays.toString(clientBytes));

            // Generate and send the server's 16 fresh random bytes
            byte[] serverBytes = Utils.generateRandomBytes(16);
            byte[] encryptedServerBytes = Utils.encryptRSA(serverBytes, clientPublicKey);
            byte[] serverSignature = Utils.signData(serverBytes, serverPrivateKey);

            // Send the encrypted server bytes and the server signature to the client
            Utils.sendBytes(clientSocket.getOutputStream(), encryptedServerBytes);
            Utils.sendBytes(clientSocket.getOutputStream(), serverSignature);

            // Concatenate the client's and server's bytes to form the AES key
            byte[] aesKeyBytes = Utils.concatenateBytes(clientBytes, serverBytes);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Receive the encrypted file content from the client
            byte[] encryptedFileContent = Utils.receiveBytes(clientSocket.getInputStream());

            // Decrypt the file content and save it to disk
            byte[] fileContent = Utils.decryptAES(encryptedFileContent, aesKey, clientBytes);

            // Generate the hashed filename and save the file
            String hashedFilename = Utils.generateHashedFilename(userid, fileName);
            Utils.saveFile(hashedFilename, fileContent);
            System.out.println("File received: " + hashedFilename);
        } else {
            System.out.println("Client signature verification failed. Terminating the connection.");
        }

        // Close the socket and finish processing the client's connection
        clientSocket.close();
    }
}
