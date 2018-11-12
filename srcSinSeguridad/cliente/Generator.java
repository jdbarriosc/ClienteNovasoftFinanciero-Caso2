package cliente;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private LoadGenerator generator;
	int numberOfTasks=1;
	int gapBetweenTaks=1000;
	
	public Generator()
	{
		Task work=createTask();
		generator=new LoadGenerator("Client - Server Load Test",numberOfTasks,work,gapBetweenTaks);
		generator.generate();
	}
	
	private Task createTask()
	{
		return new ClientServerTask();
	}

	
	public static void main (String ... args)
	{
		@SuppressWarnings("unused")
		Generator gen = new Generator();
		
		System.out.println("TERMINO PRUEBAS");
		System.out.println("Empezadas: "+gen.numberOfTasks +"\nTerminadas: "+ClienteSinSeguridad.contadorTransacciones);
		System.out.println("Promedio Tiempos Verificación: "+((double)ClienteSinSeguridad.sumaTiemposVerificacion/((double)ClienteSinSeguridad.contadorTransacciones)));
		System.out.println("Promedio Tiempos Consulta: "+((double)ClienteSinSeguridad.sumaTiemposConsulta/((double)ClienteSinSeguridad.contadorTransacciones)));
		System.out.println("Promedio Porcentaje CPU: "+(ClienteSinSeguridad.sumaTiempoCpu/ClienteSinSeguridad.cantTomadaCpu));
	}
}
