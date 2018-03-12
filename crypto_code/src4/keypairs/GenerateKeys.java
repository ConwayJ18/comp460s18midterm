package src4.keypairs;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerateKeys {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GenerateKeys(int keylength) //sets key parameters
        throws NoSuchAlgorithmException, NoSuchProviderException {

        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keylength);

    }

    public void createKeys() { //generates actual keys

        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();

    }

    public PrivateKey getPrivateKey() { //returns private key
        return this.privateKey;
    }

    public PublicKey getPublicKey() { //returns public key
        return this.publicKey;
    }

    public void writeToFile(String path, byte[] key) throws IOException { //Used to output keys to file

        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();

    }

    public static void main(String[] args)
                throws NoSuchAlgorithmException, NoSuchProviderException, IOException {

        GenerateKeys gk_Alice; //Will be Alice's key object
        GenerateKeys gk_Bob; //Will be Bob's key object

        gk_Alice = new GenerateKeys(1024);
        gk_Alice.createKeys(); //Create Alice's keys
        gk_Alice.writeToFile("KeyPair/publicKey_Alice", gk_Alice.getPublicKey().getEncoded()); //Write out public key
        gk_Alice.writeToFile("KeyPair/privateKey_Alice", gk_Alice.getPrivateKey().getEncoded()); //Write out private key

        gk_Bob = new GenerateKeys(1024); //Repeat above for Bob
        gk_Bob.createKeys();
        gk_Bob.writeToFile("KeyPair/publicKey_Bob", gk_Bob.getPublicKey().getEncoded());
        gk_Bob.writeToFile("KeyPair/privateKey_Bob", gk_Bob.getPrivateKey().getEncoded());

    }

}
