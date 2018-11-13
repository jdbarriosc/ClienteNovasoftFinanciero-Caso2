package cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.xml.bind.DatatypeConverter;


import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Cliente
{
	public static final String DIRECCION = "localhost";
	//	public static final String DIRECCION = "192.168.0.17";
	public static int contadorTransacciones=0;
	public static long sumaTiemposVerificacion=0l;
	public static long sumaTiemposConsulta=0l;
	public static double cantTomadaCpu=0;
	public static double sumaTiempoCpu=0;


	public static final BlockCipher engine = new DESEngine();

	public static String ls = " ";

	public Cliente() throws Exception 
	{
		String[]comandos=new String[4];
		comandos[0]="HOLA";
		comandos[1]="ALGORITMOS:AES:RSA:HMACMD5";
		comandos[2]="Certificado del Cliente";
		comandos[3]="OK";
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
		String fromUser="";

		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
		rsa.initialize(1024,new SecureRandom());
		KeyPair keyPair = rsa.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey pk = null;

		String certificadoServidor = " ";
		String llaveSimetricaServidor = " ";
		X509Certificate cert = null;
		boolean vaAConsultar=false;
		int it=0;
		while (ejecutar&&it<5)
		{
			getSystemCpuLoad();

			if(it<=3) {
				System.out.println("Escriba el mensaje para enviar (Hint:"+comandos[it]+") :");
				fromUser = comandos[it];
			}
			else if(it==4) {
				System.out.println("Ingrese el c�digo de identificaci�n de cuenta (N�mero Entero) :");
				fromUser = ((int)(Math.random()*500))+"";
			}
			it++;

			System.out.println("Cliente: " + fromUser);
			if(vaAConsultar)
			{
				byte[] decodedKey = DatatypeConverter.parseHexBinary(ls);
				SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

				byte[] e = cifrarSimetrico(originalKey, fromUser);
				System.out.println(e);
				String consultaCifradaString = DatatypeConverter.printHexBinary(e);
				escritor.println(consultaCifradaString);
				tiempoConsulta = System.currentTimeMillis();
				System.out.println("Cliente (Consulta Cifrada): " + fromUser);
				System.out.println("Empezo a tomar el tiempo");
				String hmac= hmacDigest(fromUser, originalKey);
				System.out.println("Cliente (HMAC): " + hmac);
				escritor.println(hmac);
			}	
			else if(fromUser.equalsIgnoreCase("Certificado del Cliente"))
			{
				java.security.cert.X509Certificate certificado = generarCertificado(keyPair);
				byte[] certificadoEnBytes = certificado.getEncoded( );
				String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
				System.out.println("Cliente: "+certificadoEnString);

				escritor.println(certificadoEnString);
				System.out.println("Servidor: " + lector.readLine());
				certificadoServidor="Va a llegar";
			}
			else 
			{
				escritor.println(fromUser);
				if(fromUser.equalsIgnoreCase("OK")) {
					tiempoVerificacion = System.currentTimeMillis();
					System.out.println("Empezo a tomar el tiempo");
					llaveSimetricaServidor="Va a llegar";
				}
			}



			if ((fromServer = lector.readLine()) != null)
			{
				
				
				if(fromServer.startsWith("OK")&&tiempoConsulta!=-1l) {
					tiempoConsulta = System.currentTimeMillis()-tiempoConsulta;
					sumaTiemposConsulta+=tiempoConsulta;
					System.out.println("Tiempo en consultar: "+tiempoConsulta+" milisegundos");
//					tiempoConsulta=-1l;

					contadorTransacciones++;
				}
				if(certificadoServidor.equals("Va a llegar"))
				{

					certificadoServidor=fromServer;
					byte[] x509cert = DatatypeConverter.parseHexBinary(certificadoServidor);

					//from byte to x509

					CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(x509cert);
					cert = (X509Certificate)certFactory.generateCertificate(in);
					pk = cert.getPublicKey();

				}
				else if(llaveSimetricaServidor.equals("Va a llegar"))
				{
					System.out.println("Servidor: " + fromServer);
					if(fromServer.equalsIgnoreCase("ERROR"))
					{
//						if(tiempoVerificacion!=-1l) 
//							sumaTiemposVerificacion-=tiempoVerificacion;
						System.out.println("Termina ejecuci�n por error!");
						break;
					}
					llaveSimetricaServidor=(descifrar(DatatypeConverter.parseHexBinary(fromServer), privateKey));
					System.out.println("Llave despu�s de descifrar: " + ls);
					String resp=(DatatypeConverter.printHexBinary(cifrar(cert.getPublicKey(), llaveSimetricaServidor)));
					System.out.println("Cliente: "+resp);
					escritor.println(resp);
					fromServer = lector.readLine();
					vaAConsultar=true;
				}
				
				System.out.println("Servidor: " + fromServer);
				if(fromServer.equals("OK")&&tiempoVerificacion!=-1l) {
					tiempoVerificacion = System.currentTimeMillis()-tiempoVerificacion;
					sumaTiemposVerificacion+=tiempoVerificacion;
					System.out.println("Tiempo en verificar: "+tiempoVerificacion+" milisegundos");
//					tiempoVerificacion=-1l;

				}
				else if(fromServer.equalsIgnoreCase("ERROR"))
				{
//					if(tiempoVerificacion!=-1l)
//						sumaTiemposVerificacion-=tiempoVerificacion;
					System.out.println("Termina ejecuci�n por error!");
					break;
				}
			}
		}
		System.out.println("Termino la transaccion!");

	
		escritor.close();
		lector.close();
		// cierre el socket y la entrada est�ndar
		socket.close();
		stdIn.close();
		
	}

	private static X509Certificate generarCertificado(KeyPair keyPair) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, ParseException {
		SimpleDateFormat dateformat2 = new SimpleDateFormat("dd-M-yyyy hh:mm:ss");
		String strdate2 = "23-10-2018 11:00:00"; 
		Date newdate = dateformat2.parse(strdate2);

		String strdate3 = "31-12-2018 11:00:00"; 
		Date newdate3 = dateformat2.parse(strdate3);

		Date startDate = newdate;              // time from which certificate is valid
		Date expiryDate = newdate3;             // time after which certificate is not valid
		BigInteger serialNumber = BigInteger.valueOf(1l);     // serial number for certificate

		@SuppressWarnings("deprecation")
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		@SuppressWarnings("deprecation")
		X509Principal dnName = new X509Principal("CN=Test CA Certificate");
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("MD2withRSA");
		X509Certificate cert = certGen.generate(keyPair.getPrivate());
		return cert;
	}


	public static final byte[] cifrar(PublicKey kp, String entrada) {
		try {
			// inicializa el cifrador
			Cipher cipher = Cipher.getInstance("RSA");

			// lee del teclado lo que se va a cifrar
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(
					System.in));
			byte[] clearText = entrada.getBytes();
			String s1 = new String(clearText);
			//System.out.println("clave original: " + s1);

			// asigna la llave publica para cifrar
			cipher.init(Cipher.ENCRYPT_MODE, kp);

			byte[] cipheredText = cipher.doFinal(clearText);
			//System.out.println("clave cifrada: " + cipheredText);

			// retorna el texto cifrado
			return cipheredText;
		} catch (Exception e) {
			System.err.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public static final String descifrar(byte[] cipheredText, PrivateKey kp) throws Exception {
		try {
			// inicializa el cifrador
			Cipher cipher = Cipher.getInstance("RSA");

			// asigna la llave privada para descifrar
			cipher.init(Cipher.DECRYPT_MODE, kp);

			byte[] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			ls = DatatypeConverter.printHexBinary(clearText);
			//System.out.println("clave original: " + s3);
			return s3;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			throw new Exception(e.getMessage());
		}
	}

	public byte [ ] sign ( String entrada, String key ) throws InvalidKeySpecException, NoSuchAlgorithmException
	{

		byte[] pBytes = DatatypeConverter.parseHexBinary(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privKey = keyFactory.generatePrivate(keySpec);
		Signature signature;

		byte[] a = DatatypeConverter.parseHexBinary(entrada);

		try
		{
			signature = Signature.getInstance ( "MD5withRSA" );
			signature.initSign ( privKey );
			signature.update(a);
			getSystemCpuLoad();


			return signature.sign ( );
		}
		catch ( Exception e )
		{
			e.printStackTrace ( );
		}

		return null;
	}

	public static byte[] cifrarSimetrico(SecretKey desKey, String entrada) {
		byte[] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			byte[] clearText = entrada.getBytes();
			String s1 = new String(clearText);
			//System.out.println("clave original: " + s1);
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			cipheredText = cipher.doFinal(clearText);
			//			String s2 = new String(cipheredText);
			//			System.out.println("clave cifrada: " + s2);
			return cipheredText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}


	}

	public static String hmacDigest(String msg, SecretKey key) {
		String digest = null;
		try {
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(key);
			byte[] bytes = mac.doFinal(msg.getBytes("ASCII"));
			StringBuffer hash = new StringBuffer();
			for (int i = 0; i < bytes.length; i++) {
				String hex = Integer.toHexString(0xFF & bytes[i]);
				if (hex.length() == 1) {
					hash.append('0');
				}
				hash.append(hex);
			}
			digest = hash.toString();
			getSystemCpuLoad();

		} catch (UnsupportedEncodingException e) {
		} catch (InvalidKeyException e) {
		} catch (NoSuchAlgorithmException e) {
		} catch (Exception e) {
		}
		return digest;
	}
	
	
	
	public static double getSystemCpuLoad() throws Exception {
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
