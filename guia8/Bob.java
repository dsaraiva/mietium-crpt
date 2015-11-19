import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;

/**
 * Created by ks on 11/11/15.
 *
 *
 */
public class Bob {

    private static Cipher cipher;
    private static String CIPHER_MODE= "AES/CTR/NoPadding";

    public static void main(String []args){
        try {

            Socket socket = new Socket("localhost",3456);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            byte rawBytes[] = diffieBobJCA(in,out);
            SecretKey key = new SecretKeySpec(rawBytes,0,16,"AES"); // chave criada apartir do sha da chave

            cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE,key);
            byte[] iv = cipher.getIV();
            //envio o IV
            out.writeObject(iv);
            out.flush();

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(rawBytes,"HmacSHA256"));

            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            byte[] ciphertext, macBytes;

            while((test=stdIn.readLine())!=null) {
                ciphertext = cipher.update(test.getBytes("UTF-8"));
                if (ciphertext != null) {
                    macBytes = mac.doFinal(ciphertext);
                    out.writeObject(ciphertext);
                    out.writeObject(macBytes);
                }
            }
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private static byte[] diffieBobJCA(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        // Bob recebe chave publica de Alice
        PublicKey alicePubKey = (PublicKey) in.readObject();

        // Bob obtem os parametros de Diffie-Hellman associados a alicePubKey
        // (faz o casting para a interface DHPublicKey para poder obter os parametros)
        DHParameterSpec dhParameterSpec = ((DHPublicKey)alicePubKey).getParams();

        // Bob cria agora o gerador de par de chaves Diffie-Hellman e incializa-o atraves dos
        // parametros dhParameterSpec que são os mesmos usados por Alice
        KeyPairGenerator bob_kPG = KeyPairGenerator.getInstance("DiffieHellman");
        bob_kPG.initialize(dhParameterSpec);

        // Cria o par de chaves
        KeyPair bobKpair = bob_kPG.generateKeyPair();

        // Bob cria o acordo de chaves Diffie-Hellman e inicializa-o com a sua chave privada
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DiffieHellman");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob envia a sua chave publica a Alice
        PublicKey bobPubKey = bobKpair.getPublic();
        out.writeObject(bobPubKey);

        // Bob executa o acordo de chaves
        bobKeyAgree.doPhase(alicePubKey, true);

        // Bob gera a segredo partilhado com Alice
        byte[] sharedSecret = bobKeyAgree.generateSecret();

        return sharedSecret;    //128bits
    }
}
