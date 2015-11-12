package com.saraiva;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class TServidor extends Thread {
    // Abre e carrega a KeyStore
    private static final KeyStoreUtils ksu = new KeyStoreUtils("portachaves","12345");
    // Para utilizar uma chave que esta guardada na keyStore
    private static final String ALIAS = "alias";
    private static final String PASS = "12345";
    private static final String CIPHER_MODE="AES/CTR/NoPadding";

    private int ct;
    protected Socket s;

    TServidor(Socket s, int c) {
        ct = c;
        this.s=s;
    }

    public void run() {
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            String test;

            // le o IV
            byte[] ivBytes = (byte[]) ois.readObject();
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            // mesma chave que no cliente
            SecretKey key = ksu.readKey(ALIAS,PASS);
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);

            cipher.init(Cipher.DECRYPT_MODE,key,iv);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);

            try {
                while (true) {
                    decrypt(ois,mac,cipher);
                }
            } catch (EOFException e) {
                System.out.println("["+ct + "]");
            } finally {
                if (ois!=null) ois.close();
                if (oos!=null) oos.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void decrypt(ObjectInputStream in, Mac mac, Cipher c) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException {
        // Le o criptograma
        byte[] criptograma = (byte[]) in.readObject();
        // Le o mac
        byte[] macBytes = (byte[]) in.readObject();

        if(!Arrays.equals(mac.doFinal(criptograma), macBytes))
        {
            System.out.println("O ficheiro foi alterado!");
            return;
        } else{// MAC iguais
            System.out.println(new String(c.update(criptograma)));
        }
    }
}
