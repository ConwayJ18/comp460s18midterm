package src4.symmetrickey;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class GenerateSymmetricKey {

    private SecretKeySpec secretKey;

    public GenerateSymmetricKey(int length, String algorithm) //creates key
        throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {

        SecureRandom rnd = new SecureRandom();
        byte [] key = new byte [length];
        rnd.nextBytes(key);
        this.secretKey = new SecretKeySpec(key, algorithm);

    }

    public SecretKeySpec getKey(){ //returns key
        return this.secretKey;
    }

    public void writeToFile(String path, byte[] key) throws IOException { //Writes out symmetric key

        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();

    }

    public static void main(String[] args)
        throws NoSuchAlgorithmException, NoSuchPaddingException, IOException {

        GenerateSymmetricKey genSK = new GenerateSymmetricKey(16, "AES"); //Generate key
        genSK.writeToFile("SymmetricKey/secretKey", genSK.getKey().getEncoded()); //Write it to a file

    }
}
