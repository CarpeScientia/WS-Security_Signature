package local.cs.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import java.util.Base64.Encoder;

import javax.xml.bind.JAXBContext;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SignatureTest {

	private static final String OUR_FAKE_CLIENT_CERT = "our.fake.client";
	private static final char[] PASSWORD_CHAR_ARRAY = "changeit".toCharArray();
	private BouncyCastleProvider bcProvider;

	@Before
	public void setup() {
		bcProvider = new BouncyCastleProvider();
	    Security.addProvider(bcProvider);
	}
	
	public X509Certificate sign(KeyPair keyPair, String subjectDN, String issuerDN, PublicKey keyToSign, boolean isCA) throws OperatorCreationException, CertificateException, IOException {
	    long now = System.currentTimeMillis();
	    Date startDate = new Date(now);

	    X500Name subjectDnName = new X500Name(subjectDN);
	    X500Name issuertDnName = new X500Name(issuerDN);
	    BigInteger certSerialNumber = new BigInteger(Long.toString(now)); 
	    Calendar calendar = Calendar.getInstance();
	    calendar.setTime(startDate);
	    calendar.add(Calendar.YEAR, 50); 

	    Date endDate = calendar.getTime();

	    String signatureAlgorithm = "SHA256WithRSA"; 

	    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

	    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuertDnName, certSerialNumber, startDate, endDate, subjectDnName, keyToSign);

	    // Extensions --------------------------

	    // Basic Constraint
	    BasicConstraints basicConstraints = new BasicConstraints(isCA); // <-- true for CA, false for EndEntity

	    certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

	    // -------------------------------------

	    return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
	}
	
	@Test //@org.junit.Ignore("only needed once")
	public void createCA() throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, KeyStoreException, InvalidAlgorithmParameterException, CertPathValidatorException, InvalidKeyException, SignatureException, URISyntaxException {
		char[] password = PASSWORD_CHAR_ARRAY;
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",bcProvider);
		KeyPair caPair = gen.generateKeyPair();
		String caDN ="C=NL, ST=NoordHolland, O=CS, OU=CTC, CN=our.fake.ca";
		X509Certificate caCert = sign(caPair, caDN, caDN, caPair.getPublic(), true );
		//System.out.println("CaCert:" + caCert.toString());
		KeyPair clientPair = gen.generateKeyPair();
		String clientDN = "C=NL, ST=NoordHolland, O=CS, OU=CTC, CN=our.fake.client";
		X509Certificate clientCert = sign(caPair, clientDN, caDN, clientPair.getPublic(), false );
		//System.out.println("ClientCert:" + clientCert.toString());
		clientCert.verify(caCert.getPublicKey());
		loadAndStore(password, caPair, caCert, "our.fake.ca");
		loadAndStore(password, clientPair, clientCert, OUR_FAKE_CLIENT_CERT);
		DigitalSignature.reload();
		Assert.assertTrue(DigitalSignature.validateKeyChain(clientCert).equals(caCert) );
	}
	@Test //@org.junit.Ignore("only needed once")
	public void createSelfSigned() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException, KeyStoreException, URISyntaxException {
		char[] password = PASSWORD_CHAR_ARRAY;
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",bcProvider);
		KeyPair keyPair = gen.generateKeyPair();
		String dn = "C=NL, ST=NoordHolland, O=CS, OU=CTC, CN=our.fake.cert";
		X509Certificate selfsigCert = sign(keyPair, dn, dn, keyPair.getPublic(), false );
		loadAndStore(password, keyPair, selfsigCert, "our.fake.cert");
		FileWriter  out =  new FileWriter ("src/test/resources/self-signed.cert");
		Encoder encoder = Base64.getMimeEncoder(64, System.getProperty("line.separator").getBytes() );
		out.write("-----BEGIN CERTIFICATE-----\n");
		out.write(encoder.encodeToString(selfsigCert.getEncoded()) );
		out.write("\n-----END CERTIFICATE-----");
		out.close();
	}
	
	@Test
	public void listKeys() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = loadKeyStore();
		String key = null;
		for(Enumeration<String> ksEnum = ks.aliases() ; ksEnum.hasMoreElements(); key = ksEnum.nextElement() ) {
			System.out.println(key );
		}
	}

	private void loadAndStore(char[] password, KeyPair pair, X509Certificate cert, String alias) throws KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, URISyntaxException {
		KeyStore ks = loadKeyStore();
		if(pair != null) {
			KeyStore.PrivateKeyEntry entry = new  KeyStore.PrivateKeyEntry(pair.getPrivate(), new Certificate[] {cert});
			ks.setEntry(alias, entry, new KeyStore.PasswordProtection(password));
		}else {
			KeyStore.TrustedCertificateEntry entry = new KeyStore.TrustedCertificateEntry(cert);
			ks.setEntry(alias, entry, null);
		}
		try(FileOutputStream out = new FileOutputStream(new File(SignatureTest.class.getClassLoader().getResource("testkeystore.jks").toURI())) ){
			ks.store(out, password);
		}
	}
	
	@Test 
	public void testDigitalSignature() throws FileNotFoundException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, URISyntaxException {
		File out = new File("src/test/resources/20553334919-01-FF11-003.xml");
		File cert = new File("src/test/resources/racer.crt");
		try(
			FileInputStream in = new FileInputStream(out);
			FileInputStream certin = new FileInputStream(cert); ){
			X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(certin);
			loadAndStore(PASSWORD_CHAR_ARRAY, null, root, "Racer CA");
			DigitalSignature.reload();
			Assert.assertFalse(DigitalSignature.get().parseSignature(in, true).isEmpty() );
		}
	}

	public String testSign() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, KeyStoreException, CertificateException, IOException, SignatureException, UnrecoverableEntryException {
		Signature rsa = Signature.getInstance("SHA1withRSA"); 
		KeyStore ks = loadKeyStore();
		KeyStore.PrivateKeyEntry entry = (PrivateKeyEntry) ks.getEntry(OUR_FAKE_CLIENT_CERT, new KeyStore.PasswordProtection(PASSWORD_CHAR_ARRAY));
		rsa.initSign(entry.getPrivateKey());
		rsa.update(Base64.getDecoder().decode("M6TrcZRC83q+GK9npNk23B4y8iI="));
		byte[] signed = rsa.sign();
		//System.out.println(
		return Base64.getEncoder().encodeToString(signed ) ; 
				//);
	}
	
	@Test
	public void testVerify() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, KeyStoreException, CertificateException, IOException, SignatureException, UnrecoverableEntryException {
		Signature rsa = Signature.getInstance("SHA1withRSA"); 
		KeyStore ks = loadKeyStore();
		X509Certificate cert = (X509Certificate) ks.getCertificate(OUR_FAKE_CLIENT_CERT );
		rsa.initVerify(cert);
		rsa.update(Base64.getDecoder().decode("M6TrcZRC83q+GK9npNk23B4y8iI="));
		boolean signed = rsa.verify(Base64.getDecoder().decode(testSign()));
		
		Assert.assertTrue(signed );
	}
	
	@Test
	public void testWSSEsigning() throws IOException, SOAPException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException {
		MessageFactory mf = MessageFactory.newInstance();
		  SOAPMessage newMessage = mf.createMessage();
		  SOAPPart soapPart = newMessage.getSOAPPart();
		  FileInputStream is = new FileInputStream("src/test/resources/ToBeSigned.xml");
		  soapPart.setContent(new StreamSource(is));
		  WSSecurityBinarySecurityToken ws = new WSSecurityBinarySecurityToken(OUR_FAKE_CLIENT_CERT);
		 
		  SOAPMessageContext context = new SOAPMessageContext() {
			  private SOAPMessage message = newMessage;
			@Override
			public void setScope(String name, Scope scope) {}
			@Override
			public Scope getScope(String name) {return null;}
			@Override
			public int size() {return 0;}
			@Override
			public boolean isEmpty() {return false;}
			@Override
			public boolean containsKey(Object key) {return false;}
			@Override
			public boolean containsValue(Object value) {return false;}
			@Override
			public Object get(Object key) {return Boolean.TRUE;}
			@Override
			public Object put(String key, Object value) {return null;}
			@Override
			public Object remove(Object key) {return null;}
			@Override
			public void putAll(Map<? extends String, ? extends Object> m) {}
			@Override
			public void clear() {}
			@Override
			public Set<String> keySet() {return null;}
			@Override
			public Collection<Object> values() {return null;}
			@Override
			public Set<Entry<String, Object>> entrySet() {return null;}
			@Override
			public SOAPMessage getMessage() {
				return message;
			}
			@Override
			public void setMessage(SOAPMessage message) {
				this.message = message;
			}
			@Override
			public Object[] getHeaders(QName header, JAXBContext context, boolean allRoles) {return null; }
			@Override
			public Set<String> getRoles() {return null;}
			  
		  };
		  ws.handleMessage(context);
		  ByteArrayOutputStream out = new ByteArrayOutputStream();
		  context.getMessage().writeTo(out);
		  ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		  WSSecurityHandler.printSoapBody(context.getMessage());
		  Assert.assertFalse(DigitalSignature.get().parseSignature(in, true).isEmpty() );
	}

	private KeyStore loadKeyStore()
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore ks = KeyStore.getInstance("JKS");
		try(InputStream in = SignatureTest.class.getClassLoader().getResourceAsStream("testkeystore.jks")){
			ks.load(in, PASSWORD_CHAR_ARRAY);
		}
		return ks;
	}
	//private key conversion openssl pkcs8 -topk8 -inform PEM -outform DER -in ./pem.key  -nocrypt > pkcs8.key
	//@Test
	public void storePrivateKeyFromFile() throws Exception {
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(Files.readAllBytes( Paths.get("src/test/resources/pkcs8.key")) );
		
		RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(privSpec);
		X509Certificate signingCert;
		try(FileInputStream inStream = new FileInputStream("src/test/resources/test.crt") ){
		signingCert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(
				 inStream);
		}
		KeyPair pair = new KeyPair(signingCert.getPublicKey(), privateKey);
		
		RSAPublicKey rsaPublic = (RSAPublicKey) signingCert.getPublicKey();
		Assert.assertEquals(rsaPublic.getModulus(), privateKey.getModulus() ); 
		
		@SuppressWarnings("restriction")
		RSAKey RSAPrivKey = sun.security.rsa.RSAKeyFactory.toRSAKey(privateKey);
		Assert.assertEquals(rsaPublic.getPublicExponent(), ((RSAPrivateCrtKey)privateKey).getPublicExponent() );
		Assert.assertEquals(rsaPublic.getPublicExponent(), ((RSAPrivateCrtKey)RSAPrivKey).getPublicExponent() );
		
		loadAndStore("changeit".toCharArray(), pair, signingCert, "newKeypair");
	}
	
	/**
	 * Find a factor of n by following the algorithm outlined in Handbook of Applied Cryptography, section
	 * 8.2.2(i). See http://cacr.uwaterloo.ca/hac/about/chap8.pdf.
	 *
	 */

	private static BigInteger findFactor(BigInteger e, BigInteger d, BigInteger n) {
	    BigInteger edMinus1 = e.multiply(d).subtract(BigInteger.ONE);
	    int s = edMinus1.getLowestSetBit();
	    BigInteger t = edMinus1.shiftRight(s);

	    for (int aInt = 2; true; aInt++) {
	        BigInteger aPow = BigInteger.valueOf(aInt).modPow(t, n);
	        for (int i = 1; i <= s; i++) {
	            if (aPow.equals(BigInteger.ONE)) {
	                break;
	            }
	            if (aPow.equals(n.subtract(BigInteger.ONE))) {
	                break;
	            }
	            BigInteger aPowSquared = aPow.multiply(aPow).mod(n);
	            if (aPowSquared.equals(BigInteger.ONE)) {
	                return aPow.subtract(BigInteger.ONE).gcd(n);
	            }
	            aPow = aPowSquared;
	        }
	    }

	}

	public static RSAPrivateCrtKey createCrtKey(RSAPublicKey rsaPub, RSAPrivateKey rsaPriv) throws NoSuchAlgorithmException, InvalidKeySpecException {

	    BigInteger e = rsaPub.getPublicExponent();
	    BigInteger d = rsaPriv.getPrivateExponent();
	    BigInteger n = rsaPub.getModulus();
	    BigInteger p = findFactor(e, d, n);
	    BigInteger q = n.divide(p);
	    if (p.compareTo(q) > 0) {
	        BigInteger t = p;
	        p = q;
	        q = t;
	    }
	    BigInteger exp1 = d.mod(p.subtract(BigInteger.ONE));
	    BigInteger exp2 = d.mod(q.subtract(BigInteger.ONE));
	    BigInteger coeff = q.modInverse(p);
	    RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, exp1, exp2, coeff);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return (RSAPrivateCrtKey) kf.generatePrivate(keySpec);

	}
}
