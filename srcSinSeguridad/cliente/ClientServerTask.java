package cliente;

import uniandes.gload.core.Task;

public class ClientServerTask extends Task {

	public void execute() {
		try {
			ClienteSinSeguridad client = new ClienteSinSeguridad();
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
