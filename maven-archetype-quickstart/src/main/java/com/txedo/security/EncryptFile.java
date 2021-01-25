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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptFile {
    public final static String RESOURCES_DIR = "";
    protected final static Logger LOGGER = Logger.getLogger(EncryptFile.class);

    public static void main(String[] args)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String log4jConfPath = "maven-archetype-quickstart\\log4j.properties";
        PropertyConfigurator.configure(log4jConfPath);

        try {
            String plainText = readFileAsString("input.data");
            KeyPair keys = LoadKeyPair("", "RSA");

            LOGGER.info(String.format("Starting encryption"));
            
            // First create an AES Key
            String secretAESKeyString = getSecretAESKeyAsString();

            // Encrypt our data with AES key
            String encryptedText = encryptTextUsingAES(plainText, secretAESKeyString);

            writeDataToFile(encryptedText);

            // Encrypt AES Key with RSA Private Key
            String encryptedAESKeyString = encryptAESKey(secretAESKeyString, keys.getPrivate());

            writeKeyToFile(encryptedAESKeyString);

            LOGGER.info(String.format("Finished encryption"));
        } catch (InvalidKeySpecException e) {
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
        File file = new File("encrypted.data");
        
        try (FileWriter fileWriter = new FileWriter(file);) {
            fileWriter.write(cipherText);
            LOGGER.info(String.format("Successfully stored encrypted data to file -> " + file));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeKeyToFile(String cipherText){
        File file = new File("encrypted.akey");
        
        try (FileWriter fileWriter = new FileWriter(file);) {
            fileWriter.write(cipherText);
            LOGGER.info(String.format("Successfully stored encrypted AES key to file -> " + file));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Create a new AES key. Uses 128 bit (weak)
    public static String getSecretAESKeyAsString() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(secKey.getEncoded());
        return encodedKey;
    }

    // Encrypt text using AES key
    public static String encryptTextUsingAES(String plainText, String aesKeyString) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
 
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(byteCipherText);
    }

    // Encrypt AES Key using RSA private key
    private static String encryptAESKey(String plainAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainAESKey.getBytes()));
    }

    private static PrivateKey generatePrivateKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
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
