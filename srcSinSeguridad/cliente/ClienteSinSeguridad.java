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

	public static final BlockCipher engine = new DESEngine();

	public static void main(String[] args) throws Exception 
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
		String fromServer = " ";
		String fromUser;

		boolean vaAConsultar=false;

		while (ejecutar)
		{
			System.out.print("Escriba el mensaje para enviar:");
			fromUser = stdIn.readLine();
			if (fromUser != null)
			{
				System.out.println("Cliente: " + fromUser);
				
				if(vaAConsultar)
				{
					escritor.println(fromUser);
					System.out.print("Escriba el mensaje para enviar:");
					fromUser = stdIn.readLine();
					if (fromUser != null)
						System.out.println("Cliente: " + fromUser);
					else { 
						System.out.println("ERROR");
						return;
					}
						
					
				}
				
				else if(fromUser.equalsIgnoreCase("Certificado del Cliente"))
					System.out.println("Servidor: " + lector.readLine());
				else if(fromUser.equalsIgnoreCase("LS"))
					vaAConsultar=true;
				

				escritor.println(fromUser);
			}
			else { 
				System.out.println("ERROR");
				return;
			}
			if ((fromServer = lector.readLine()) != null)
				System.out.println("Servidor: " + fromServer);
			
		}
		escritor.close();
		lector.close();
		// cierre el socket y la entrada estándar
		socket.close();
		stdIn.close();
	}

	
}
