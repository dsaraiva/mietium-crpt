
import javax.crypto.spec.DHParameterSpec;
import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;

/**
 * Created by ks on 11/20/15.
 */
public class Servidor {

    private static final int PRIME_SIZE = 1024; // tamanho em bits do 'p' e 'g'
    static private int tcount;
    private static DHParameterSpec dhParameterSpec;

    static public void main(String []args) {
        tcount = 0;
        try {
            // Criacao dos parametros Diffie-Hellman (demora muito tempo por isso cria apenas uma vez aquando da iniciacao do servidor)
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
            paramGen.init(PRIME_SIZE);
            AlgorithmParameters params = paramGen.generateParameters();
            dhParameterSpec = params.getParameterSpec(DHParameterSpec.class);
            FileInputStream keyStoreInputStream = new FileInputStream("Servidor.p12");

            ServerSocket ss = new ServerSocket(3494);

            while(true) {
                Socket s = ss.accept();
                tcount++;
                AliceThread dt = new AliceThread(s,tcount,dhParameterSpec);
                dt.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}