package saraiva;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class Main {

    private static final String ALIAS = "alias";
    private static final String PASS = "12345";
    private static final String INFILE = "texto.txt";
    private static final String ENCFILE = "enc";
    private static final String DECFILE = "enc";

    private static final KeyStoreUtils ksu = new KeyStoreUtils("portachaves","12345");
    private static final AES_Utlis aesUtlis = new AES_Utlis();




    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        KeyStoreUtils ksu = new KeyStoreUtils("portachaves","12345");
        SecretKey key = ksu.readKey(ALIAS,PASS);
        
        switch (args[0]){
            case "-genkey":
                genkey();
                break;
            case "-enc":
                aesUtlis.encrypt(key,args[1],args[2]); // Encripta o ficheiro
                break;
            case "-dec":
                aesUtlis.decrypt(key, args[1], args[2]); // Desencripta o ficheiro
                break;
            default:
                System.out.println("Argumento invalido!");
                ksu.close(); // fecha a keystore
                help();
                break;
        }
    }


    private static void help(){
        System.out.println("Modo de utilização:");
        System.out.println(
                "prog -genkey \n"+
                "prog -enc <infile> <outfile>\n"+
                "prog -dec <infile> <outfile>\n"
        );
    }

    private static void genkey(){
        SecretKey k = aesUtlis.generateAESKey(128); // poderia gerar password atraves de palavra dada pelo utilizador
        System.out.println("Escolha o ALIAS:");
        String alias = System.console().readLine();
        char[] pass = System.console().readPassword();
        ksu.addKey(k,alias,pass);
    }
}
