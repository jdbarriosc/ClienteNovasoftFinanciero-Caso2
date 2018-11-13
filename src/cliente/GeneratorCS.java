package cliente;

import java.util.ArrayList;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class GeneratorCS {
	
	private LoadGenerator generator;
	int numberOfTasks=80;
	int gapBetweenTaks=100;
	
	public GeneratorCS() throws InterruptedException
	{
		Task work=createTask();
		generator=new LoadGenerator("Client - Server Load Test",numberOfTasks,work,gapBetweenTaks);
		generator.generate();
		
		
		Thread.sleep(10000);
		System.out.println("TERMINO PRUEBAS");
		System.out.println("Empezadas: "+numberOfTasks +"\nTerminadas: "+Cliente.contadorTransacciones);

		System.out.println("\n\nPromedio Tiempos Verificación: "+((double)Cliente.sumaTiemposVerificacion/((double)Cliente.contadorTransacciones)));
		System.out.println("Promedio Tiempos Consulta: "+((double)Cliente.sumaTiemposConsulta/((double)Cliente.contadorTransacciones)));
		System.out.println("Perdidas: "+(numberOfTasks-Cliente.contadorTransacciones));
		System.out.println("Promedio Porcentaje CPU: "+(Cliente.sumaTiempoCpu/Cliente.cantTomadaCpu));
		
		tVerificacion=((double)Cliente.sumaTiemposVerificacion/((double)Cliente.contadorTransacciones));
		tConsulta=((double)Cliente.sumaTiemposConsulta/((double)Cliente.contadorTransacciones));
		perdidas=(numberOfTasks-Cliente.contadorTransacciones);
		porcentajeCPU=(Cliente.sumaTiempoCpu/Cliente.cantTomadaCpu);
	}
	
	private Task createTask()
	{
		return new ClientCSServerTask();
	}

	private double tConsulta;
	private double tVerificacion;
	private int perdidas;
	private double porcentajeCPU;


	public static void main (String ... args) throws InterruptedException
	{
		@SuppressWarnings("unused")	
		GeneratorCS gen = new GeneratorCS();
	}
	
	
	public double gettConsulta() {
		return tConsulta;
	}

	public void settConsulta(double tConsulta) {
		this.tConsulta = tConsulta;
	}

	public double gettVerificacion() {
		return tVerificacion;
	}

	public void settVerificacion(double tVerificacion) {
		this.tVerificacion = tVerificacion;
	}

	public int getPerdidas() {
		return perdidas;
	}

	public void setPerdidas(int perdidas) {
		this.perdidas = perdidas;
	}

	public double getPorcentajeCPU() {
		return porcentajeCPU;
	}

	public void setPorcentajeCPU(double porcentajeCPU) {
		this.porcentajeCPU = porcentajeCPU;
	}

	
}
