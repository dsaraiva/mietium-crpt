package com.saraiva;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;

public class Cliente {

    // Abre e carrega a KeyStore
    private static final KeyStoreUtils ksu = new KeyStoreUtils("portachaves","12345");
    // Para utilizar uma chave que esta guardada na keyStore
    private static final String ALIAS = "alias";
    private static final String PASS = "12345";

    private static final String CIPHER_MODE="AES/CTR/NoPadding";

    static public void main(String []args) {
        try {
            Socket s = new Socket("localhost",4567);

            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

            SecretKey key = ksu.readKey(ALIAS,PASS);

            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE,key);

            byte[] iv = cipher.getIV();
            //envio iv
            oos.writeObject(iv);
            oos.flush();

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key); // deveria usar outra chave


            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            byte[] ciphertext, macBytes;

            // faz update enquanto le do teclado( se for muito grande);
            // quando le tudo do teclado calcula o mac;
            // envia o criptograma e o respectivo mac
            while((test=stdIn.readLine())!=null) {
                ciphertext = cipher.update(test.getBytes("UTF-8"));
                if (ciphertext != null) {
                    macBytes = mac.doFinal(ciphertext);
                    oos.writeObject(ciphertext);
                    oos.writeObject(macBytes);
                }
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}