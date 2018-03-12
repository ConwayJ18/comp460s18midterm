package src4.bob;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class EncryptKey {

    private Cipher cipher;

    public EncryptKey(PublicKey key, File originalKeyFile, File encryptedKeyFile, String cipherAlgorithm) //Is called to do the encryption
        throws IOException, GeneralSecurityException{

        this.cipher = Cipher.getInstance(cipherAlgorithm);
        encryptFile(getFileInBytes(originalKeyFile), encryptedKeyFile, key);

    }

    public void encryptFile(byte[] input, File output, PublicKey key) //Does the encryption
        throws IOException, GeneralSecurityException {

        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));

    }

    private void writeToFile(File output, byte[] toWrite) //Writes out the encrypted key
        throws IllegalBlockSizeException, BadPaddingException, IOException{

        output.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
        System.out.println("The key was successfully encrypted and stored in: " + output.getPath());

    }

    public byte[] getFileInBytes(File f) throws IOException{ //Reads input file

        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;

    }

}
