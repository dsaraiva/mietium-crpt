package saraiva;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
/**
 * Created by ks on 11/20/15.
 */
public class Bob {

    private static Cipher cipher;
    private static String CIPHER_MODE= "AES/CTR/NoPadding";

    public static void main(String []args){
        try {

            Socket socket = new Socket("localhost",3499);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            byte rawBytes[] = stationToStationBob(in,out);
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
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    private static byte[] stationToStationBob(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {

        // Abre a chave publica do Alice
        FileInputStream publicKeyFile = new FileInputStream(new File("ApubKey"));
        ObjectInputStream objInS = new ObjectInputStream(publicKeyFile);
        //Guardo a chave publica de Alice
        PublicKey APubKey = (PublicKey) objInS.readObject();
        objInS.close();
        publicKeyFile.close();

        //Abre a "minha" chave privada
        FileInputStream BprivKeyFile = new FileInputStream(new File("BprivKey"));
        ObjectInputStream objectInputStream = new ObjectInputStream(BprivKeyFile);
        //Guardo a minha chave privada
        PrivateKey bobPrivKey = (PrivateKey) objectInputStream.readObject();
        objectInputStream.close();
        BprivKeyFile.close();

        Signature signature = Signature.getInstance("DSA");
        signature.initSign(bobPrivKey);

        //Recebe a chave publica de Alice (DH)
        PublicKey alicePubKey = (PublicKey) in.readObject();
        DHParameterSpec dhParameterSpec = ((DHPublicKey)alicePubKey).getParams();
        KeyPairGenerator bob_kPG = KeyPairGenerator.getInstance("DiffieHellman");
        bob_kPG.initialize(dhParameterSpec);
        KeyPair bobKpair = bob_kPG.generateKeyPair();
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DiffieHellman");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob envia a sua chave publica DH a Alice
        PublicKey bobPubKey = bobKpair.getPublic();
        out.writeObject(bobPubKey);

        // Primeiro a chave da Alice e depois a do Bob (DH keys)
        signature.update(alicePubKey.getEncoded());
        signature.update(bobPubKey.getEncoded());
        byte[] Bsign = signature.sign();

        //Envio a assinatura
        out.writeObject(Bsign);
        out.flush();

        // Bob recebe a assinatura de Alice
        byte[] Asign = (byte[]) in.readObject();

        //Bob verifica a assinatura de Alice
        signature.initVerify(APubKey); //chave publica lida do ficheiro
        signature.update(alicePubKey.getEncoded());
        signature.update(bobPubKey.getEncoded());

        // Bob verifica a chave de Alice (comparando com a chave que gera apartir das chaves DH)
        boolean verifies = signature.verify(Asign);

        if(verifies){
            //System.out.println("Assinatura de Alice verificada");
            // Bob executa o acordo de chaves
            bobKeyAgree.doPhase(alicePubKey, true);
            // Bob gera a segredo partilhado com Alice
            byte[] sharedSecret = bobKeyAgree.generateSecret();

            return sharedSecret;    //128bits
        }
        else
            return null;
    }
}
