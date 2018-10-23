package cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Cliente
{
	public static final String DIRECCION = "localhost";

	public static void main(String[] args) throws IOException 
	{
		boolean ejecutar = true;
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		try
		{
			socket = new Socket(DIRECCION, 8080);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (Exception e)
		{
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}

		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String fromServer;
		String fromUser;

		while (ejecutar)
		{
			System.out.print("Escriba el mensaje para enviar:");
			fromUser = stdIn.readLine();
			if (fromUser != null)
			{
				System.out.println("Cliente: " + fromUser);
				if (fromUser.equalsIgnoreCase("OK"))
				{
					ejecutar = false;
				}
				escritor.println(fromUser);
			}

			if ((fromServer = lector.readLine()) != null)
			{
				System.out.println("Servidor: " + fromServer);
			}
		}
		escritor.close();
		lector.close();
		// cierre el socket y la entrada estándar
		socket.close();
		stdIn.close();
	}
}
