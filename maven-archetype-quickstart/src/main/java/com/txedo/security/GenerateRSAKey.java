package com.txedo.security;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerateRSAKey {
  
  protected final static Logger LOGGER = Logger.getLogger(GenerateRSAKey.class);
  
  public static final int KEY_SIZE = 2048;

  public static void main(String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
    Security.addProvider(new BouncyCastleProvider());

    String log4jConfPath = "maven-archetype-quickstart\\log4j.properties";
    PropertyConfigurator.configure(log4jConfPath);
    
    LOGGER.setLevel(org.apache.log4j.Level.INFO);
    LOGGER.info("BouncyCastle provider added.");
    
    KeyPair keyPair = generateRSAKeyPair();
    RSAPrivateKey priv = (RSAPrivateKey) keyPair.getPrivate();
    RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
    
    writePemFile(priv, "RSA PRIVATE KEY", "id_rsa");
    writePemFile(pub, "RSA PUBLIC KEY", "id_rsa.pub");
  }

  private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(KEY_SIZE);
    
    KeyPair keyPair = generator.generateKeyPair();
    LOGGER.info("RSA key pair generated.");
    return keyPair;
  }

  private static void writePemFile(Key key, String description, String filename)
      throws FileNotFoundException, IOException {
    PemFile pemFile = new PemFile(key, description);
    pemFile.write(filename);
    
    LOGGER.info(String.format("%s successfully writen in file %s.", description, filename));
  }

}
