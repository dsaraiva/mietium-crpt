import java.net.*;

public class Servidor {

	static private int tcount;
	
    static public void main(String []args) {
	tcount = 0;
	try {
	    ServerSocket ss = new ServerSocket(4567);

	    
	    while(true) {
		Socket s = ss.accept();
		tcount++;
		TServidor ts = new TServidor(s,tcount);
	        ts.start();
	    }
	}
	catch (Exception e){
	    e.printStackTrace();
	}
    }
}
