import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by ks on 10/30/15.
 *
 * Le chave de Alice e depois envio a minha chave pra Alice
 */
public class Bob {

    private static Cipher cipher;
    private static String CIPHER_MODE= "AES/CTR/NoPadding";
    static final BigInteger p = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    static final BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");

    public static void main(String []args){
        try {

            Socket socket = new Socket("localhost",3456);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            byte rawBytes[] = diffieB(in,out);
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
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /** BOB
     * Primeiro recebo e so depois envio
     */
    private static byte[] diffieB(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        BigInteger y = new BigInteger(p.bitLength()-1,new SecureRandom());
        BigInteger gPowY = g.modPow(y,p);
        // Le chave publica de Alice (g^x)
        BigInteger gPowX_ = (BigInteger) in.readObject();

        // Envio a minha chave
        out.writeObject(gPowY);
        out.flush();

        BigInteger gpowXY = gPowX_.modPow(y,p);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte rawBytes[] = sha256.digest(gpowXY.toByteArray());
        return rawBytes;
    }
}