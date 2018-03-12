package src5.bob;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class EncryptKey {

    private Cipher cipher1;
    private Cipher cipher2;

    public EncryptKey(PublicKey pubKey, PrivateKey privKey, File originalKeyFile, File encryptedKeyFile, String cipherAlgorithm) //Is called to do the encryption
        throws IOException, GeneralSecurityException{

        this.cipher1 = Cipher.getInstance(cipherAlgorithm);
        this.cipher2 = Cipher.getInstance(cipherAlgorithm);
        encryptFile(getFileInBytes(originalKeyFile), encryptedKeyFile, pubKey, privKey);

    }

    public void encryptFile(byte[] input, File output, PublicKey pubKey, PrivateKey privKey) //Does the encryption
        throws IOException, GeneralSecurityException {

        this.cipher1.init(Cipher.ENCRYPT_MODE, pubKey);
        this.cipher2.init(Cipher.ENCRYPT_MODE,  privKey);
        writeToFile(output, this.cipher2.doFinal(this.cipher1.doFinal(input)));

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
