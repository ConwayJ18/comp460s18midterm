//package src6.bob;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.SecretKeySpec;

public class StartEncryption {

    public PrivateKey getPrivate(String filename, String algorithm) throws Exception { //Used to get Bob's private key

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);

    }

    public PublicKey getPublic(String filename, String algorithm) throws Exception { //Used to get Alice's public key

        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);

    }

    public SecretKeySpec getSecretKey(String filename, String algorithm) throws IOException{ //Used to get symmetric key
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        return new SecretKeySpec(keyBytes, algorithm);

    }

/*    public SecretKeySpec getHash(String filename) throws IOException{ //Used to get symmetric key
        byte[] hashBytes = Files.readAllBytes(new File(filename).toPath());
        return hashBytes;
    }
*/
    public static void main(String[] args)
        throws IOException, GeneralSecurityException, Exception{

        StartEncryption startEnc = new StartEncryption();

        File originalKeyFile = new File("SymmetricKey/secretKey"); //Grab original symmetric key
        File encryptedKeyFile = new File("EncryptedFiles/encryptedSecretKey"); //Choose where to encrypt to
        new EncryptKey(startEnc.getPublic("KeyPair/publicKey_Alice", "RSA"), startEnc.getPrivate("KeyPair/privateKey_Bob", "RSA"),
                originalKeyFile, encryptedKeyFile, "RSA"); //Encrypt symmetric key

        File originalDataFile = new File("confidential.txt"); //Choose file to encrypt
        File encryptedDataFile = new File("EncryptedFiles/encryptedFile"); //Choose output for encryption
        new EncryptData(originalDataFile, encryptedDataFile,
                startEnc.getSecretKey("SymmetricKey/secretKey", "AES"), "AES"); //Encrypt file

        new SecureHash(encryptedKeyFile, encryptedDataFile); //Create hash files

    }

}
