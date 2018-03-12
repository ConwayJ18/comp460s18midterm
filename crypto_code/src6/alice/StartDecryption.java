package src6.alice;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import javax.crypto.spec.SecretKeySpec;

public class StartDecryption {

    public PrivateKey getPrivate(String filename, String algorithm) throws Exception { //Used to fetch Alice's private key

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);

    }

    public PublicKey getPublic(String filename, String algorithm) throws Exception { //Used to fetch Bob's public key

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);

    }

    public SecretKeySpec getSecretKey(String filename, String algorithm) throws IOException{ //Used to fetch symmetric key

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        return new SecretKeySpec(keyBytes, algorithm);

    }

    public static boolean validateSecureHash(File fileReceived, File fileCalculated) throws IOException{ //Used to get symmetric key
        byte[] f1 = Files.readAllBytes(fileReceived.toPath());
        byte[] f2 = Files.readAllBytes(fileCalculated.toPath());
        if(Arrays.equals(f1, f2))
        {
            return true;
        }
        return false;
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException, Exception{

        StartDecryption startDec = new StartDecryption();

        File encryptedKeyReceived = new File("EncryptedFiles/encryptedSecretKey"); //Fetches encrypted symmetric key
        File encryptedFileReceived = new File("EncryptedFiles/encryptedFile"); //Fetches encrypted message
        File keyHashReceived = new File("EncryptedFiles/keyHash"); //Fetches received keyHash
        File dataHashReceived = new File("EncryptedFiles/dataHash"); //Fetches received dataHash

        new SecureHash(encryptedKeyReceived, encryptedFileReceived); //Rehash key & data
        File keyHashCalculated = new File("DecryptedFiles/keyHash"); //Fetch those hashes
        File dataHashCalculated = new File("DecryptedFiles/dataHash");

        if(validateSecureHash(keyHashReceived, keyHashCalculated) && validateSecureHash(dataHashReceived, dataHashCalculated))
        {
                File decreptedKeyFile = new File("DecryptedFiles/SecretKey"); //Decide where to send decrypted key
                new DecryptKey(startDec.getPrivate("KeyPair/privateKey_Alice", "RSA"), startDec.getPublic("KeyPair/publicKey_Bob", "RSA"),
                        encryptedKeyReceived, decreptedKeyFile, "RSA"); //Run the key decryption

                File decryptedFile = new File("DecryptedFiles/decryptedFile"); //Decide where to send decrypted message
                new DecryptData(encryptedFileReceived, decryptedFile,
                        startDec.getSecretKey("DecryptedFiles/SecretKey", "AES"), "AES"); //Run the message decryption
        }
        else{
                System.out.println("Either the key or the file has been corrupted.");
        }
    }
}
