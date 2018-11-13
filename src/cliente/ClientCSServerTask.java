package cliente;

import uniandes.gload.core.Task;

public class ClientCSServerTask extends Task {

	public void execute() {
		try {
			Cliente client = new Cliente();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
	}
	
	public void success()
	{
		System.out.println(Task.OK_MESSAGE);
	}
}
