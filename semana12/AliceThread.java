import sun.security.x509.X500Name;
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
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;

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
    private static byte[] stationToStationAlice(ObjectInputStream in, ObjectOutputStream out) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ClassNotFoundException, SignatureException, KeyStoreException, CertificateException, UnrecoverableKeyException {

        FileInputStream keyStoreInputStream = new FileInputStream("Servidor.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(keyStoreInputStream,"1234".toCharArray());

        PrivateKey APrivKey = (PrivateKey) ks.getKey("Servidor","1234".toCharArray());

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

        //Alice recebe certificado de Bob
        CertPath bobCert = (CertPath) in.readObject();

        // Alice verifica o certificado no CA
        valCertificate(bobCert);
        // Se certificado for verificado (como???) continua a verificar cenas

        // Alice le a chave publica de Bob do certificado
        X509Certificate bobC = (X509Certificate) bobCert.getCertificates().get(0);
        PublicKey bPubKey = bobC.getPublicKey();

        //Alice verifica assinatura de Bob
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(bPubKey);  //chave publica do bob (lida do certificado)
        signature.update(alicePubKey.getEncoded());
        signature.update(bobPubKey.getEncoded());

        // Alice verifica a assinatura de Bob (comparando com a chave que gera apartir das chaves DH)
        boolean verifies_sign = signature.verify(Bsign);

        // Alice verefica o nome que esta no certificado de forma a garantir autenticidade do cliente
        String certName = (new X500Name(bobC.getSubjectX500Principal().toString())).getCommonName();
        // verificar se certName comeca com a sub string "Cliente"
        boolean verifies_subject = certName.contains("Cliente");

        // Se for confirmada a assinatura e o nome (dado que o certificado tbm ja foi confirmado)
        if(verifies_sign && verifies_subject){
            signature.initSign(APrivKey);
            signature.update(alicePubKey.getEncoded());
            signature.update(bobPubKey.getEncoded());
            byte[] Asign = signature.sign();

            //Alice envia a assinatura ao bob
            out.writeObject(Asign);

            //Alice envia o certificado ao Bob
            Certificate[] certArray = ks.getCertificateChain("Servidor");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));
            out.writeObject(certPath);

            //Alice executa o acorde de chaves
            aliceKeyAgree.doPhase(bobPubKey, true);

            // Alice gera a segredo partilhado com bob
            byte[] sharedSecret = aliceKeyAgree.generateSecret();

            return sharedSecret;    //128bits
        }
        else
            return null;
    }

    private static void valCertificate(CertPath cp){
        try {

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            Certificate cacert = certificateFactory.generateCertificate(new FileInputStream("CA.cer"));
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            TrustAnchor anchor = new TrustAnchor((X509Certificate) cacert, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);

            // Validacao
            CertPathValidatorResult cpvResult = cpv.validate(cp, params);


        } catch (NoSuchAlgorithmException | CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException iape) {
            iape.printStackTrace();
            System.err.println("Erro de validação: " + iape);
            System.exit(1);
        } catch (CertPathValidatorException cpve) {
            System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
            System.err.println("Posição do certificado causador do erro: "
                    + cpve.getIndex());
        }
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
