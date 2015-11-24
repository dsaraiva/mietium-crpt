import java.io.*;
import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * Created by ks on 11/20/15.
 *
 * Executei 2 vezes; uma para gerar ApubKey e AprivKey; outra para gerar BpubKey e BprivKey
 */
public class ParChaves {

    static public void main(String[] args) {
        try {

            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DSA");
            paramGen.init(1024);

            AlgorithmParameters params = paramGen.generateParameters();

            DSAParameterSpec dsaParameterSpec = params.getParameterSpec(DSAParameterSpec.class);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(dsaParameterSpec);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            saveKey("BpubKey",publicKey);
            saveKey("BprivKey",privateKey);

        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private static void saveKey(String fileName, Key key) {
        try {
            FileOutputStream fos = new FileOutputStream(new File(fileName));
            ObjectOutputStream oos = new ObjectOutputStream(fos);

            oos.writeObject(key);
            oos.flush();
            fos.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
