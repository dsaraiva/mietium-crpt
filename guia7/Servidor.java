import java.net.*;

public class Servidor {

    static private int tcount;

    static public void main(String []args) {
        tcount = 0;
        try {
            ServerSocket ss = new ServerSocket(3456);

            while(true) {
                Socket s = ss.accept();
                tcount++;
                AliceThread dt = new AliceThread(s,tcount);
                dt.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}