import javax.crypto.spec.DHParameterSpec;
import java.net.*;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;

/**
 * Created by ks on 11/11/15.
 *
 * Baseado em https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#AppD
 *
 * AlgorithmParameterGenerator: Esta classe é usada para gerar um conjunto de parametros a serem utilizados por um determinado
 * algoritmo, neste caso o Diffie-Hellman; é assim inicializado com 'p e 'g' de tamanho PRIME_SIZE
 * DHParameterSpec: Especifica os parametros usados no allgoritmo Diffie-Hellman ('p' e 'g').

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

            ServerSocket ss = new ServerSocket(3456);

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