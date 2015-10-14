package saraiva;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by ks on 10/7/15.
 */

public class AES_Utlis {

    private static final int MAC_BYTES = 32;
    private static final int IV_BYTES = 16;
    private static final String MODE = "AES/CBC/PKCS5Padding";

    private static Cipher cipher;

    public AES_Utlis(){
        try {
            cipher = Cipher.getInstance(MODE);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    // Methods

    // Create a new AES key
    public SecretKey generateAESKey(int key_size){
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(key_size);
            return kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private IvParameterSpec createIvParameterSpec(){
        SecureRandom random = new SecureRandom();
        byte[] iv_bytes = new byte[IV_BYTES];
        random.nextBytes(iv_bytes);
        return (new IvParameterSpec(iv_bytes));
    }

    // **************** ENCRYPT METHOD **********************************************************
    public void encrypt(SecretKey key, String infile, String outfile) {
        try {
            IvParameterSpec ivParameterSpec = createIvParameterSpec();
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            File in = new File(infile);
            FileInputStream fis = new FileInputStream(in);
            FileOutputStream fos = new FileOutputStream(new File(outfile));

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);// poderia criar uma key para o MAC e guardar na KeyStore

            int n;
            byte[] data = new byte[1024];
            byte[] data_out;
            byte[] iv = ivParameterSpec.getIV();
            fos.write(iv);
            fos.flush();
            mac.update(iv); // O MAC vai incluir [IV + CRIPTOGRAMA]

            while ((n = fis.read(data, 0, data.length)) != -1) {
                data_out = cipher.update(data,0,n);
                mac.update(data_out);   // MAC aos dados ja cifrados!
                fos.write(data_out);
                fos.flush();
            }
            data_out = cipher.doFinal();
            fos.write(data_out);
            mac.update(data_out);
            byte[] mac_bytes = mac.doFinal();
            fos.write(mac_bytes);   // No final do ficheiro escrevo os bytes do MAC

            fos.close();
            fis.close();

            System.out.println("\nFicheiro '"+infile+"' encriptado com sucesso!");
           // System.exit(0);

        } catch (IOException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }


// **************** DECRYPT METHOD **********************************************************
    public void decrypt(SecretKey key, String infile, String outfile) {
        try {
            RandomAccessFile fis = new RandomAccessFile(infile,"r");
            long fileSize = fis.length();
            FileOutputStream fos = new FileOutputStream(new File(outfile));

            // Vou gerar o MAC do criptograma e comparar com o que esta no final do ficheiro
            Mac newMAC = Mac.getInstance("HmacSHA256");
            newMAC.init(key);
            int n;
            byte[] data = new byte[1024];
            long readedBytes = 0;

            while( (n=fis.read(data,0,data.length)) != -1){
                if((readedBytes + n) > (fileSize-MAC_BYTES)){ //para ler ficheiro apenas ate inicio de MAC
                    newMAC.update(data,0, (int) (fileSize-MAC_BYTES-readedBytes));
                    break;
                }
                newMAC.update(data);
                readedBytes+=n;
            }

            byte[] newMAC_bytes = newMAC.doFinal();

            //Ler o MAC contido no ficheiro
            byte[] mac = new byte[MAC_BYTES];
            fis.seek(fileSize - MAC_BYTES); // aponta para a posicao inicial do MAC
            fis.read(mac,0,MAC_BYTES);


            // Se os MAC forem iguais vou desencriptar o ficheiro; Senao aborta o programa
            if(!Arrays.equals(mac,newMAC_bytes)){
                System.out.println("O ficheiro foi alterado!");
                System.exit(1);
            }
            else { // MAC iguais
                fis.seek(0); // Aponta para o inicio do ficheiro

                byte[] iv = new byte[16]; // Ler os 16 bytes correspondentes ao IV; Uso-os para fazer o cipher.init()
                fis.read(iv);
                cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));

                byte[] data_out;
                readedBytes = IV_BYTES; // porque ja li os bytes do IV

                while(( n=fis.read(data,0,data.length)) != -1){
                    if((readedBytes + n) > (fileSize-MAC_BYTES)){  //para ler ficheiro apenas ate inicio de MAC
                        data_out = cipher.update(data,0, (int) (fileSize-MAC_BYTES-readedBytes));
                        fos.write(data_out);
                        fos.flush();
                        break;
                    }
                    readedBytes += n;
                    data_out = cipher.update(data,0,n);
                    fos.write(data_out);
                    fos.flush();
                }

                data_out = cipher.doFinal();
                fos.write(data_out);

                System.out.println("Ficheiro desencriptado com sucesso");

                fos.close();
                fis.close();
            }
        } catch (InvalidAlgorithmParameterException | IOException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
