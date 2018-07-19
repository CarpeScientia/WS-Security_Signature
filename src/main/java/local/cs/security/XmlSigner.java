package local.cs.security;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

public final class XmlSigner {
	
	private static final Logger log = LoggerFactory.getLogger(XmlSigner.class);
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static byte[] sign(JAXBElement<?> o, String keyAlias, String JAXBcontextPath) throws Exception {
		// Create a DOM XMLSignatureFactory that will be used to
		// generate the enveloped signature.
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		// Create a Reference to the enveloped document (in this case,
		// you are signing the whole document, so a URI of "" signifies
		// that, and also specify the SHA1 digest algorithm and
		// the ENVELOPED Transform.
		Reference ref = fac.newReference
		 ("", fac.newDigestMethod(DigestMethod.SHA1, null),
		  Collections.singletonList
		   (fac.newTransform
		    (Transform.ENVELOPED, (TransformParameterSpec) null)),
		     null, null);

		// Create the SignedInfo.
		SignedInfo si = fac.newSignedInfo
		 (fac.newCanonicalizationMethod
		  (CanonicalizationMethod.INCLUSIVE,
		   (C14NMethodParameterSpec) null),
		    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
		     Collections.singletonList(ref));
		

		KeyStore.PrivateKeyEntry keyEntry = loadKey(keyAlias);
		X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

		// Create the KeyInfo containing the X509Data.
		KeyInfoFactory kif = fac.getKeyInfoFactory();

		List x509Content = new ArrayList();
		x509Content.add(cert.getSubjectX500Principal().getName());
		x509Content.add(cert);
		X509Data xd = kif.newX509Data(x509Content);
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
		
		Document doc = serializeToDocument(o, JAXBcontextPath);

		// Create a DOMSignContext and specify the RSA PrivateKey and
		// location of the resulting XMLSignature's parent element.
		DOMSignContext dsc = new DOMSignContext
		    (keyEntry.getPrivateKey(), doc.getDocumentElement());

		// Create the XMLSignature, but don't sign it yet.
		XMLSignature signature = fac.newXMLSignature(si, ki);

		// Marshal, generate, and sign the enveloped signature.
		signature.sign(dsc);
		
		// Output Document to System.out
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.transform(new DOMSource(doc), new StreamResult(out));
        return out.toByteArray();
	}

	protected static KeyStore.PrivateKeyEntry loadKey(String keyalias) throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, UnrecoverableEntryException {
		// Load the KeyStore and get the signing key and certificate.
		KeyStore ks = KeyStore.getInstance("JKS");
		InputStream in = XmlSigner.class.getClassLoader().getResourceAsStream("testkeystore.jks");//TODO change this to property file def
		ks.load(in, "changeit".toCharArray());//TODO change this to property file def
		KeyStore.PrivateKeyEntry keyEntry =
		    (KeyStore.PrivateKeyEntry) ks.getEntry
		        (keyalias, new KeyStore.PasswordProtection("changeit".toCharArray()));
		//System.out.println(keyEntry.getCertificate() );
		return keyEntry;
	}
	
	protected static Document serializeToDocument(JAXBElement<?> o, String JAXBcontextPath) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	        dbf.setNamespaceAware(true);
	        DocumentBuilder db = dbf.newDocumentBuilder();
	        Document document = db.newDocument();
	        JAXBContext jaxbContext = getJaxbContext(JAXBcontextPath);//JAXBContext.newInstance(o.getClass());
            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(o, document);
            return document;
        } catch (JAXBException | ParserConfigurationException e) {
            log.warn("either could not create JAXB instance or initalize serializer", e);
        } 
         return null;
     }
	
	public static void toXml(JAXBElement<?> element) {
	    try {
	        JAXBContext jc = JAXBContext.newInstance(element.getValue().getClass());  
	        Marshaller marshaller = jc.createMarshaller();  
	        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);  
	        StringWriter wr = new StringWriter();
	        marshaller.marshal(element, wr);
	        System.out.println(wr.toString());
	    } catch (Exception e) {
	        e.printStackTrace();
	    }      
	}
	
	public static JAXBContext getJaxbContext(String JAXBcontextPath) throws JAXBException {
		JAXBContext jaxbContext;
		ClassLoader loader = XmlSigner.class.getClassLoader();
		if(loader == null) {
			log.error("classloader null, we got loaded by the bootstrap classloader?");
			throw new RuntimeException("classloader null, we got loaded by the bootstrap classloader?");
		}
		
		jaxbContext = JAXBContext.newInstance(JAXBcontextPath, loader);
		return jaxbContext;
	}
}
