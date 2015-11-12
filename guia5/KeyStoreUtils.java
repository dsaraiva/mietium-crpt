package com.saraiva;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

/**
 * Created by ks on 10/7/15.
 */

public class KeyStoreUtils{

    private static final String TYPE = "JCEKS";

    private KeyStore ks;
    private String KeyStoreName;
    private char[] password;
    FileInputStream keyInputStream;

    // Open and load an existing KeyStore
    public KeyStoreUtils(String KeyStoreName, String passWord) {
        this.password = passWord.toCharArray();
        this.KeyStoreName = KeyStoreName;
        try {
            this.ks = KeyStore.getInstance(TYPE);
            this.keyInputStream = new FileInputStream(KeyStoreName);
            ks.load(keyInputStream, password);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.out.println("Ficheiro '"+KeyStoreName+"' nao existe.");

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
    }

    // Create and load a new KeyStore
    public KeyStoreUtils(){
        this.KeyStoreName =  System.console().readLine();
        this.password = System.console().readPassword();
        try {
            this.ks = KeyStore.getInstance("JCEKS");
            ks.load(null,password);

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

// Methods_________________________________________________________________________________________________________________
//   ______________________________________________________________________________________________________________________

    public void addKey(SecretKey key, String alias,  char[] keyPassword){
        try {
            KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(keyPassword);
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(key);
            ks.setEntry(alias,secretKeyEntry,protectionParameter);
            saveKeyStore();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private void saveKeyStore(){
        try {
            FileOutputStream fos = new FileOutputStream(KeyStoreName);
            ks.store(fos,password);
            System.out.println("KeyStore gravada");
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            e.printStackTrace();
        }
    }

    public SecretKey readKey(String alias, String keyPassword){

        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(keyPassword.toCharArray());
        try {
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) ks.getEntry(alias,protectionParameter);
            return secretKeyEntry.getSecretKey();
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }
    public void close(){
        try {
            keyInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
