package cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;

import javax.crypto.Cipher;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class ClienteSinSeguridad
{
	public static final String DIRECCION = "localhost";
//	public static final String DIRECCION = "192.168.0.17";
	public static int contadorTransacciones=0;
	public static long sumaTiemposVerificacion=0l;
	public static long sumaTiemposConsulta=0l;
	public static double cantTomadaCpu=0;
	public static double sumaTiempoCpu=0;



	public static final BlockCipher engine = new DESEngine();

	public ClienteSinSeguridad() throws Exception 
	{
		String[]comandos=new String[7];
		comandos[0]="HOLA";
		comandos[1]="ALGORITMOS:AES:RSA:HMACMD5";
		comandos[2]="Certificado del Cliente";
		comandos[3]="OK";
		comandos[4]="LS";
		comandos[5]="\"Codigo de identificación de cuenta (Sólo numeros)\"";
		comandos[6]="\"Codigo de identificacion HMACCMD5\"";

		long tiempoVerificacion=-1l;
		long tiempoConsulta=-1l;

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
		String fromServer = " ";
		String fromUser;

		boolean vaAConsultar=false;
		int it=0;
		
		while (ejecutar&&it<6)
		{
			getSystemCpuLoad();

			System.out.println("Escriba el mensaje para enviar:");
			System.out.println("Hint: "+comandos[it]);
			if(it<=4)
				fromUser = comandos[it];
			else 
				fromUser = ((int)(Math.random()*500))+"";
			it++;

		
			if (fromUser != null)
			{
				
				System.out.println("Cliente: " + fromUser);
				escritor.println(fromUser);
			
				
				if(fromUser.equalsIgnoreCase("OK")&&it==4) {
					tiempoVerificacion = System.currentTimeMillis();
					System.out.println("Empezo a tomar el tiempo");

				}
				else if(vaAConsultar)
				{
					tiempoConsulta = System.currentTimeMillis();
					System.out.println("Empezo a tomar el tiempo");

					System.out.println("Escriba el mensaje para enviar:");
					System.out.println("Hint: "+comandos[it]);
					fromUser = ((int)(Math.random()*500))+"";
					it++;
					System.out.println("Cliente: " + fromUser);
					escritor.println(fromUser);	
				}
				else if(fromUser.equalsIgnoreCase("Certificado del Cliente"))
					System.out.println("Servidor: " + lector.readLine());
				else if(fromUser.equalsIgnoreCase("LS"))
					vaAConsultar=true;
				getSystemCpuLoad();


			}
			else { 
				System.out.println("ERROR");
				return;
			}
			fromServer = lector.readLine();
			if (fromServer != null) {
				
				if(fromServer.equals("OK")&&tiempoVerificacion!=-1l) {
					tiempoVerificacion = System.currentTimeMillis()-tiempoVerificacion;
					sumaTiemposVerificacion+=tiempoVerificacion;
					System.out.println("Tiempo en verificar: "+tiempoVerificacion+" milisegundos");
					tiempoVerificacion=-1l;

				}
				if((fromServer.startsWith("OK")||fromServer.startsWith("ERROR"))&&tiempoConsulta!=-1l) {
					tiempoConsulta = System.currentTimeMillis()-tiempoConsulta;
					sumaTiemposConsulta+=tiempoConsulta;
					System.out.println("Tiempo en consultar: "+tiempoConsulta+" milisegundos");
					tiempoConsulta=-1l;
					contadorTransacciones++;

				}
				getSystemCpuLoad();

				System.out.println("Servidor: " + fromServer);
			}
			
		}
		System.out.println("Fin de la transacción");
		escritor.close();
		lector.close();
		// cierre el socket y la entrada estándar
		socket.close();
		stdIn.close();
	
		
	}
	
	
	public double getSystemCpuLoad() throws Exception {
		 MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		 ObjectName name = ObjectName.getInstance("java.lang:type=OperatingSystem");
		 AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });
		 if (list.isEmpty()) return Double.NaN;
		 Attribute att = (Attribute)list.get(0);
		 Double value = (Double)att.getValue();
		 // usually takes a couple of seconds before we get real values
		 if (value == -1.0) return Double.NaN;
		 // returns a percentage value with 1 decimal point precision
		 sumaTiempoCpu+=((int)(value * 1000) / 10.0);
		 cantTomadaCpu++;
		 return ((int)(value * 1000) / 10.0);
		 }
	
}
