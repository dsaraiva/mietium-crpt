import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

/**
 * Created by ks on 10/30/15.
 *
 * 1o envio a minha chave e depois vou ler a de Bob
 */
public class AliceThread extends Thread{

    private static String CIPHER_MODE= "AES/CTR/NoPadding";
    private static final BigInteger p = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    private static final BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    private static Socket socket;
    private int client;

    public AliceThread(Socket socket, int client){
        this.socket = socket;
        this.client=client;
    }

    public void run(){
        try{

            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

            byte[] rawBytes = diffieA(in,out);
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
    private static byte[] diffieA(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        BigInteger x = new BigInteger(p.bitLength()-1,new SecureRandom());
        BigInteger gPowX = g.modPow(x,p);
        // Envio a minha chave publica a Bob
        out.writeObject(gPowX);
        out.flush();
        // Le chave publica de Bob (g^y)
        BigInteger gPowY = (BigInteger) in.readObject();

        BigInteger gpowYX = gPowY.modPow(x,p);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte rawBytes[] = sha256.digest(gpowYX.toByteArray());
        return rawBytes;
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
