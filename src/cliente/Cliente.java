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

public class Cliente
{
	public static final String DIRECCION = "localhost";

	public static final BlockCipher engine = new DESEngine();

	public static void main(String[] args) throws IOException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, ParseException, ClassNotFoundException, CertificateException, CMSException 
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

		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
		rsa.initialize(1024,new SecureRandom());
		KeyPair keyPair = rsa.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey pk = null;

		String certificadoServidor = " ";
		String llaveSimetricaServidor = " ";
		X509Certificate cert = null;

		while (ejecutar)
		{
			System.out.print("Escriba el mensaje para enviar:");
			fromUser = stdIn.readLine();
			if (fromUser != null)
			{
				System.out.println("Cliente: " + fromUser);
				if(fromUser.equalsIgnoreCase("Certificado del Cliente"))
				{
					java.security.cert.X509Certificate certificado = generarCertificado(keyPair);
					byte[] certificadoEnBytes = certificado.getEncoded( );
					String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);

					escritor.println(certificadoEnString);
					System.out.println("Servidor: " + lector.readLine());
					certificadoServidor="Va a llegar";
				}
				else
				{
					if(fromUser.equalsIgnoreCase("OK"))
						llaveSimetricaServidor="Va a llegar";
					escritor.println(fromUser);
				}

			}
			if ((fromServer = lector.readLine()) != null)
			{
				if(certificadoServidor.equals("Va a llegar"))
				{

					certificadoServidor=fromServer;
					byte[] x509cert = DatatypeConverter.parseHexBinary(certificadoServidor);
					//byte[] x509cert=certificateSerialization.getCertificateByte();

					//from byte to x509

					CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(x509cert);
					cert = (X509Certificate)certFactory.generateCertificate(in);
					//					ByteArrayInputStream bis = new ByteArrayInputStream(x509cert);
					//					ObjectInput in = new ObjectInputStream(bis);
					//					X509Certificate cert = (X509Certificate) in.readObject(); 
					//					bis.close();
					pk = cert.getPublicKey();

				}
				else if(llaveSimetricaServidor.equals("Va a llegar"))
				{
					System.out.println("Servidor: " + fromServer);
					llaveSimetricaServidor=DatatypeConverter.printHexBinary(decryptData(DatatypeConverter.parseHexBinary(fromServer),privateKey));
					String resp=(DatatypeConverter.printHexBinary(encryptData(DatatypeConverter.parseHexBinary(llaveSimetricaServidor),cert)));
					System.out.println("Cliente: "+resp);
					escritor.println(resp);
					fromServer = lector.readLine();
				}
				System.out.println("Servidor: " + fromServer);
			}
		}
		escritor.close();
		lector.close();
		// cierre el socket y la entrada estándar
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
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
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

	//	public static byte[] Encrypt(String keys, byte[] plainText) {
	//        byte[] key = keys.getBytes();
	//        byte[] ptBytes = plainText;
	//        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
	//        cipher.init(true, new KeyParameter(key));
	//        byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];
	//        int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
	//        try {
	//            cipher.doFinal(rv, tam);
	//        } catch (Exception ce) {
	//            ce.printStackTrace();
	//        }
	//        return rv;
	//    }

	//    public static byte[] Decrypt(byte[] key2, byte[] cipherText) {
	//        byte[] key = key2;
	//        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));
	//        cipher.init(false, new KeyParameter(key));
	//        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
	//        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
	//        try {
	//            cipher.doFinal(rv, tam);
	//        } catch (Exception ce) {
	//            ce.printStackTrace();
	//        }
	//        return rv;
	//    }

	public static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException
	{
		byte[] decryptedData = null;
		if (null != encryptedData && null != decryptionKey)
		{
			CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

			Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
			KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
			JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);

			return recipientInfo.getContent(recipient);
		}
		return decryptedData;
	}

	public static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException
	{
		byte[] encryptedData = null;
		if (null != data && null != encryptionCertificate)
		{
			CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();

			JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
//			cmsEnvelopedDataGenerator.addRecipientInfoGenerator(transKeyGen);
			CMSTypedData msg = new CMSProcessableByteArray(data);
			OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build();
			CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg,encryptor);
			encryptedData = cmsEnvelopedData.getEncoded();
		}
		return encryptedData;
	}
}
