import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

/**
 * Created by ks on 08/11/15.
 * Guiao da semana 8
 * Protocolo Diffie-Hellman no JCA
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

            byte[] rawBytes = diffieAliceJCA(in,out);
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
    private static byte[] diffieAliceJCA(ObjectInputStream in, ObjectOutputStream out) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ClassNotFoundException {
        // Alice cria o gerador de par de chaves Diffie-Hellman e incializa-o atraves dos parametros dhParameterSpec
        KeyPairGenerator alice_kPG = KeyPairGenerator.getInstance("DiffieHellman");
        alice_kPG.initialize(dhParameterSpec);

        // Cria o par de chaves
        KeyPair aliceKpair = alice_kPG.generateKeyPair();

        // Alice cria o acordo de chaves Diffie-Hellman e inicializa-o com a sua chave privada
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DiffieHellman");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice envia a sua chave publica a Bob
        PublicKey alicePubKey = aliceKpair.getPublic();
        out.writeObject(alicePubKey);

        //Alice recebe chave publica de Bob
        PublicKey bobPubKey = (PublicKey)in.readObject();

        //Alice executa o acorde de chaves
        aliceKeyAgree.doPhase(bobPubKey, true);

        // Alice gera a segredo partilhado com bob
        byte[] sharedSecret = aliceKeyAgree.generateSecret();

        return sharedSecret;    //128bits
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
