package com.saraiva;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

//       1a versao:
//      SecureRandom random = new SecureRandom();
//      byte[] key_bytes = new byte[16];    //(128bits para RC4)
//      random.nextBytes(key_bytes);
//      SecretKey key = new SecretKeySpec(key_bytes,"RC4");

        SecretKey key;
        Cipher c = Cipher.getInstance("RC4");

        if(args.length < 1 || args.length> 4){
            System.out.println("****** ERRO ******");
            help();
            System.exit(1);
        }

        switch (args[0]){
            case "-genkey":
                generateKey(args[1]);
                break;
            case "-enc":
                key = readKey(args[1]);
                c.init(Cipher.ENCRYPT_MODE, key);
                encrypt(args[2],args[3],c);
                break;
            case "-dec":
                key = readKey(args[1]);
                c.init(Cipher.DECRYPT_MODE, key);
                decrypt(args[2], args[3], c);
                break;
            default:
                System.out.println("Argumento invalido!");
                help();
                break;
        }
    }

    private static void help(){
        System.out.println("Modo de utilização:");
        System.out.print(
                "prog -genkey <keyfile>\n"+
                "prog -enc <keyfile> <infile> <outfile>\n"+
                "prog -dec <keyfile> <infile> <outfile>\n"
        );
    }

    private static void generateKey(String keyPath) {
        File key_file = new File(keyPath);
        try {
            KeyGenerator kg = KeyGenerator.getInstance("RC4");
            kg.init(128);
            SecretKey key = kg.generateKey();
            byte[] key_bytes = key.getEncoded();
            FileOutputStream out = new FileOutputStream(key_file);
            out.write(key_bytes);
            out.flush();
            out.close();

            System.out.println("Chave criada com sucesso!");
            System.exit(0);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.exit(1);
    }

    private static SecretKey readKey(String keyfile) {
        try {
            FileInputStream fis = new FileInputStream(new File(keyfile));
            //int n_bytes = fis.available();
            //byte [] key_bytes = new byte[n_bytes];
            // Como determinar o tamanho da chave? (para funcionar com AES etc)
            byte[] key_bytes = new byte[16];
            fis.read(key_bytes);
            SecretKey key = new SecretKeySpec(key_bytes, "RC4");
            return key;

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void encrypt(String infile, String outfile, Cipher cipher) {
        try {
            FileInputStream fis = new FileInputStream(new File(infile));
            FileOutputStream fos = new FileOutputStream(new File(outfile));
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);

            int n;
            byte[] data = new byte[1024];   // le 1024 bytes de cada vez -> menos acessos a disco -> mais rapido!
            while ((n = fis.read(data, 0, data.length)) != -1) {
                cos.write(data, 0, n);
                cos.flush();
            }
            cos.close();
            fis.close();
            fos.close();

            System.out.println("Ficheiro "+infile+" encriptado com sucesso!");
            System.exit(0);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.exit(1);
    }

    private static void decrypt(String infile, String outfile, Cipher cipher){

        try {
            FileInputStream fis = new FileInputStream(new File(infile));
            CipherInputStream cis = new CipherInputStream(fis,cipher);
            FileOutputStream fos = new FileOutputStream(new File(outfile));

            int n;
            byte[] data = new byte[1024];

            while( (n=cis.read(data, 0, data.length)) !=-1){
                fos.write(data,0,n);
                fos.flush();
            }
            cis.close();
            fis.close();
            fos.close();

            System.out.println("Ficheiro '"+infile+"' desencriptado com sucesso para '"+outfile+"'.");
            System.exit(0);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.exit(1);
    }
}