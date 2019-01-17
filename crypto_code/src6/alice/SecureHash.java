//package src6.alice;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;
import java.security.*;
import java.io.*;

public class SecureHash {

    private File keyFile;
    private File dataFile;

    public SecureHash(File keyFile, File dataFile)
    {
        this.keyFile = keyFile;
        this.dataFile = dataFile;
        createSecureHash(keyFile, dataFile);
    }

    public static void writeToFile(String path, byte[] hash) throws IOException { //Used to output keys to file

        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(hash);
        fos.flush();
        fos.close();
    }

    public static String byteToString(byte[] b)
    {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < b.length; i++)
        {
            buf.append(Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1));
        }
        return buf.toString();
    }

    public static void createSecureHash(File keyFile, File dataFile)
    {
        File file1 = keyFile;
        File file2 = dataFile;

        FileInputStream fin1 = null;
        FileInputStream fin2 = null;

        try
        {

            fin1 = new FileInputStream(file1);
            fin2 = new FileInputStream(file2);
            byte fileContent1[] = new byte[(int)file1.length()];
            byte fileContent2[] = new byte[(int)file2.length()];

            try
            {
                  MessageDigest md1 = MessageDigest.getInstance("SHA-256");
                  MessageDigest md2 = MessageDigest.getInstance("SHA-256");
                  byte[] keyHash=md1.digest(fileContent1);
                  byte[] dataHash=md2.digest(fileContent2);
                  writeToFile("DecryptedFiles/keyHash", keyHash);
                  writeToFile("DecryptedFiles/dataHash", dataHash);
            }
            catch (NoSuchAlgorithmException e)
            {
                  e.printStackTrace();
            }

            fin1.read(fileContent1);
            fin2.read(fileContent2);
            String s1 = new String(fileContent1);
            String s2 = new String(fileContent2);
           // System.out.println("File content: " + s1);
           // System.out.println("File content: " + s2);

        }
        catch (FileNotFoundException e)
        {
            System.out.println("File not found" + e);
        }
        catch (IOException ioe)
        {
            System.out.println("Exception while reading file " + ioe);
        }
        finally
        {
            try
            {
                if (fin1 != null && fin2 != null)
                {
                    fin1.close();
                    fin2.close();
                }
            }
            catch (IOException ioe)
            {
                System.out.println("Error while closing stream: " + ioe);
            }
        }
    }
}
