package src6.alice;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class DecryptKey {

    private Cipher cipher1;
    private Cipher cipher2;

    public DecryptKey(PrivateKey privateKey, PublicKey publicKey, File encryptedKeyReceived, File decreptedKeyFile, String algorithm)
        throws IOException, GeneralSecurityException {

        this.cipher1 = Cipher.getInstance(algorithm);
        this.cipher2 = Cipher.getInstance(algorithm);
        decryptFile(getFileInBytes(encryptedKeyReceived), decreptedKeyFile, privateKey, publicKey);

    }

    public void decryptFile(byte[] input, File output, PrivateKey key, PublicKey pubKey)
        throws IOException, GeneralSecurityException {

        this.cipher1.init(Cipher.DECRYPT_MODE, key);
        this.cipher2.init(Cipher.DECRYPT_MODE, pubKey);
        writeToFile(output, this.cipher1.doFinal(this.cipher2.doFinal(input)));

    }

    private void writeToFile(File output, byte[] toWrite)
        throws IllegalBlockSizeException, BadPaddingException, IOException{

        output.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();

    }

    public byte[] getFileInBytes(File f) throws IOException{

        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;

    }

}
