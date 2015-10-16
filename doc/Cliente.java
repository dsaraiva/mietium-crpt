import java.net.*;
import java.io.*;

public class Cliente {

    static public void main(String []args) {
	try {
	    Socket s = new Socket("localhost",4567);

	    ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

	    String test;
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
	    while((test=stdIn.readLine())!=null) {
			oos.writeObject(test);
	    }
	}
	catch (Exception e){
	    e.printStackTrace();
	}
    }
}
