package saraiva;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

/**
 * Created by ks on 11/20/15.
 */


public class AliceThread extends Thread {

    private static String CIPHER_MODE= "AES/CTR/NoPadding";
    private static DHParameterSpec dhParameterSpec;
    private final Socket socket;
    private final int client;

    public AliceThread(Socket socket, int client, DHParameterSpec dhParameterSpec){
        this.dhParameterSpec=dhParameterSpec;
        this.socket = socket;
        this.client=client;
    }

    public void run(){
        try{
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

            byte[] rawBytes = stationToStationAlice(in,out);
            SecretKey key = new SecretKeySpec(rawBytes,0,16,"AES");
            //le o IV enviado pelo cliente (BOB)
            byte[] ivBytes = (byte[]) in.readObject();
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher c= Cipher.getInstance(CIPHER_MODE);
            c.init(Cipher.DECRYPT_MODE,key,iv);

            //Crio o MAC
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(rawBytes,"HmacSHA256"));

            try {
                while (true){
                    decrypt(in,mac,c);
                }
            } catch (EOFException e){
                System.out.println(client+" esta offline!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /** ALICE
     * Primeiro envia e so depois leio
     */
    private static byte[] stationToStationAlice(ObjectInputStream in, ObjectOutputStream out) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ClassNotFoundException, SignatureException {

        // Abre e guarda a chave publica do Bob
        FileInputStream bPubKeyFile= new FileInputStream(new File("BpubKey"));
        ObjectInputStream ois = new ObjectInputStream(bPubKeyFile);
        PublicKey bPubKey = (PublicKey) ois.readObject();
        bPubKeyFile.close();
        ois.close();
        //Abre e guarda a "minha" chave privada
        FileInputStream fis = new FileInputStream(new File("AprivKey"));
        ObjectInputStream objectInputStream = new ObjectInputStream(fis);
        PrivateKey APrivKey = (PrivateKey) objectInputStream.readObject();
        fis.close();
        objectInputStream.close();

        KeyPairGenerator alice_kPG = KeyPairGenerator.getInstance("DiffieHellman");
        alice_kPG.initialize(dhParameterSpec);
        KeyPair aliceKpair = alice_kPG.generateKeyPair();
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DiffieHellman");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice envia a sua chave publica a Bob (DH)
        PublicKey alicePubKey = aliceKpair.getPublic();
        out.writeObject(alicePubKey);

        //Alice recebe chave publica de Bob (DH)
        PublicKey bobPubKey = (PublicKey)in.readObject();

        //Alice recebe a assinatura de Bob
        byte[] Bsign = (byte[]) in.readObject();

        //Alice verifica assinatura de Bob
        Signature signature = Signature.getInstance("DSA");
        signature.initVerify(bPubKey);  //chave publica do bob (lida do ficheiro)
        signature.update(alicePubKey.getEncoded());
        signature.update(bobPubKey.getEncoded());
        // Alice verifica a chave de Bob (comparando com a chave que gera apartir das chaves DH)
        boolean verifies = signature.verify(Bsign);

        if(verifies){
            signature.initSign(APrivKey);
            signature.update(alicePubKey.getEncoded());
            signature.update(bobPubKey.getEncoded());
            byte[] Asign = signature.sign();

            //Envio a assinatura ao bob
            out.writeObject(Asign);

            //Alice executa o acorde de chaves
            aliceKeyAgree.doPhase(bobPubKey, true);

            // Alice gera a segredo partilhado com bob
            byte[] sharedSecret = aliceKeyAgree.generateSecret();

            return sharedSecret;    //128bits
        }
        else
            return null;
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
