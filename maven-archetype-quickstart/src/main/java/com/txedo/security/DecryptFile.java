package com.txedo.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DecryptFile {
    protected final static Logger LOGGER = Logger.getLogger(DecryptFile.class);
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            String log4jConfPath = "maven-archetype-quickstart\\log4j.properties";
            PropertyConfigurator.configure(log4jConfPath);

            String encrypteddata = readFileAsString("encrypted.data");
            String encryptedAESKeyString = readFileAsString("encrypted.akey");
            
            KeyPair keys = LoadKeyPair("", "RSA");

            LOGGER.info(String.format("Starting decryption"));
            
            // First decrypt the AES Key with RSA Public key
            String decryptedAESKeyString = decryptAESKey(encryptedAESKeyString, keys.getPublic());

            // Now decrypt data using the decrypted AES key!
            String decryptedText = decryptTextUsingAES(encrypteddata, decryptedAESKeyString);

            writeDataToFile(decryptedText);

            LOGGER.info(String.format("Finished decryption"));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String readFileAsString(String filePath) throws java.io.IOException {
        StringBuffer fileData = new StringBuffer(1000);
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead = 0;
        while ((numRead = reader.read(buf)) != -1) {
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
            buf = new char[1024];
        }
        reader.close();
        System.out.println(fileData.toString());
        return fileData.toString();
    }

    private static void writeDataToFile(String cipherText){
        File file = new File("output.data");
        
        try (FileWriter fileWriter = new FileWriter(file);) {
            fileWriter.write(cipherText);
            LOGGER.info(String.format("Successfully stored encrypted data to file -> " + file));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Decrypt text using AES key
    public static String decryptTextUsingAES(String encryptedText, String aesKeyString) throws Exception {
 
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
 
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] bytePlainText = aesCipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(bytePlainText);
    }

    // Decrypt AES Key using RSA public key
    private static String decryptAESKey(String encryptedAESKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey)));
    }

    private static PrivateKey generatePrivateKey(KeyFactory factory, String filename)
            throws InvalidKeySpecException, FileNotFoundException, IOException {
        PemFile pemFile = new PemFile(filename);
        byte[] content = pemFile.getPemObject().getContent();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        return factory.generatePrivate(privKeySpec);
    }

    private static PublicKey generatePublicKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
        PemFile pemFile = new PemFile(filename);
        byte[] content = pemFile.getPemObject().getContent();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
        return factory.generatePublic(pubKeySpec);
    }

    private static KeyPair LoadKeyPair(String path, String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchProviderException {
        
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        PublicKey pub = generatePublicKey(factory, path + "id_rsa.pub");
        PrivateKey priv = generatePrivateKey(factory, path + "id_rsa");

		return new KeyPair(pub, priv);
	}
}
