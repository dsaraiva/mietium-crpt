import sun.security.x509.X500Name;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
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
public class Bob {

    private static Cipher cipher;
    private static String CIPHER_MODE= "AES/CTR/NoPadding";

    public static void main(String []args){
        try {

            Socket socket = new Socket("localhost",3494);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            byte rawBytes[] = stationToStationBob(in,out);
            SecretKey key = new SecretKeySpec(rawBytes,0,16,"AES");

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
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | SignatureException | UnrecoverableKeyException | KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }


    private static byte[] stationToStationBob(ObjectInputStream in, ObjectOutputStream out) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, KeyStoreException, UnrecoverableKeyException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {

        //Abre e guarda a "minha" chave privada presente na keystore
        FileInputStream keyStoreInputStream = new FileInputStream("Cliente.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(keyStoreInputStream,"1234".toCharArray());
        PrivateKey bobPrivKey = (PrivateKey) ks.getKey("Cliente1","1234".toCharArray());
        keyStoreInputStream.close();
        // Inicializacao assinatura
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(bobPrivKey);

        // Acesso à "cadeia de certificação"
        Certificate[] certArray = ks.getCertificateChain("Cliente1");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));

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

        //Bob envia a assinatura
        out.writeObject(Bsign);
        out.flush();

        //Bob envia o certificado
        out.writeObject(certPath);

        // Bob recebe a assinatura de Alice
        byte[] Asign = (byte[]) in.readObject();

        // Bob recebe o certificado de Alice
        CertPath aliceCert = (CertPath) in.readObject();

        // Bob verifica o certificado no CA
        valCertificate(aliceCert);

        // Bob le a chave publica de Alice do certificado
        X509Certificate AliceC = (X509Certificate) aliceCert.getCertificates().get(0);
        PublicKey APubKey = AliceC.getPublicKey();

        //Bob verifica a assinatura de Alice
        signature.initVerify(APubKey); //chave publica lida do certificado
        signature.update(alicePubKey.getEncoded());
        signature.update(bobPubKey.getEncoded());

        // Bob verifica a chave de Alice (comparando com a chave que gera apartir das chaves DH)
        boolean verifies = signature.verify(Asign);

        // Alice verefica o nome que esta no certificado de forma a garantir autenticidade do cliente
        String certName = (new X500Name(AliceC.getSubjectX500Principal().toString())).getCommonName();

        // verificar se certName comeca com a sub string "Cliente"
        boolean verifies_subject = certName.equals("Servidor");

        System.out.println("Assinatura: "+verifies+"\nNome no certificado: "+verifies_subject);


        // Se for confirmada a assinatura e o nome (dado que o certificado tbm ja foi confirmado)
        if(verifies && verifies_subject){
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
    private static void valCertificate(CertPath cp){
        try {

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            Certificate cacert = certificateFactory.generateCertificate(new FileInputStream("CA.cer"));
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            TrustAnchor anchor = new TrustAnchor((X509Certificate) cacert, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);
            // Validacao
            cpv.validate(cp, params);

        } catch (NoSuchAlgorithmException | CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException iape) {
            iape.printStackTrace();
            System.err.println("Erro de validação: " + iape);
            System.err.println("Erro de validação: " + iape);
            System.exit(1);
        } catch (CertPathValidatorException cpve) {
            System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
            System.err.println("Posição do certificado causador do erro: "
                    + cpve.getIndex());
        }
    }


}
