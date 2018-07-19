package local.cs.security;




import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class DigitalSignature {
	private static final Logger log = LoggerFactory.getLogger(DigitalSignature.class);
	private static final String PROPERTIES_FILE = "application";

	private static DigitalSignature instance = new DigitalSignature();

	private X509Certificate[] trustedCerts;
	private Map<X500Principal, TrustAnchor> trustedAnchors;

	private DigitalSignature()  {
		ResourceBundle properties = ResourceBundle.getBundle(PROPERTIES_FILE);
		String storename = properties.getString("anchor-keystore");
		String storepass = properties.getString("anchor-keystore-password");
		try{
			KeyStore keyStore =  loadKeystore(storename, storepass.toCharArray());
			this.trustedCerts = loadAnchorCerts(keyStore);
			this.trustedAnchors = convertToTrustAnchors(trustedCerts);
		}catch(GeneralSecurityException | IOException g) {
			log.error("Failed to load Anchor certificates ", g);
		}
	}


	private Map<X500Principal, TrustAnchor> convertToTrustAnchors(X509Certificate[] trustedCerts2) {
		Map<X500Principal, TrustAnchor> anchors = new HashMap<>();
		for(X509Certificate cert : trustedCerts2 ) {
			anchors.put( cert.getSubjectX500Principal(), new TrustAnchor(cert, null) );
		}
		return anchors;
	}


	public static DigitalSignature get() {
		return instance;
	}

	public static void reload() {
		instance = new DigitalSignature();
	}


	private static X509Certificate[] loadAnchorCerts( KeyStore keyStore) throws KeyStoreException  {
		X509Certificate[] certs = new X509Certificate[keyStore.size()];
		int i = 0;
		Enumeration<String> alias = keyStore.aliases();

		while (alias.hasMoreElements()) {
			certs[i++] = (X509Certificate) keyStore.getCertificate(alias
					.nextElement());
		}

		return certs;
	}

	public static X509Certificate validateKeyChain(X509Certificate client ) throws CertificateException,
	InvalidAlgorithmParameterException, NoSuchAlgorithmException,
	NoSuchProviderException, CertPathValidatorException {
		return  get().validateKeyChainInternal(client);
	}


	private X509Certificate validateKeyChainInternal(X509Certificate client ) throws CertificateException,
	InvalidAlgorithmParameterException, NoSuchAlgorithmException,
	NoSuchProviderException, CertPathValidatorException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CertPathValidator validator = CertPathValidator.getInstance("PKIX");
		List<Certificate> list = Arrays.asList(new Certificate[] { client });
		PKIXCertPathValidatorResult result = null;
		TrustAnchor anchor = trustedAnchors.get(client.getIssuerX500Principal());
		if(anchor == null) {
			throw new CertificateException("Issuer " + client.getIssuerDN() + " is not part of the Trusted Anchor set, the certificate is not trusted!");
		}
		Set<TrustAnchor> anchorSet= Collections.singleton(anchor);
		PKIXParameters params = new PKIXParameters(anchorSet );
		params.setRevocationEnabled(false);
		CertPath path = cf.generateCertPath(list);
		try {
			result = (PKIXCertPathValidatorResult) validator.validate(path, params);
		}catch(CertPathValidatorException e) {
			log.warn("failed to validate with " + anchor.getTrustedCert().toString() + " for client " + client.toString());
			try {
				client.verify(anchor.getTrustedCert().getPublicKey());
			} catch (InvalidKeyException | SignatureException e1) {
				log.warn("backup verify failed as well " );
			}
			return null;
		}

		return result.getTrustAnchor().getTrustedCert();
	}

	public static boolean isSelfSigned(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException,
			NoSuchProviderException {
		try {
			PublicKey key = cert.getPublicKey();

			cert.verify(key);
			return true;
		} catch (SignatureException sigEx) {
			return false;
		} catch (InvalidKeyException keyEx) {
			return false;
		}
	}

	private static KeyStore loadKeystore( String storename, char[] storepass ) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance("JKS");
		try (InputStream in = DigitalSignature.class.getClassLoader().getResourceAsStream(storename) ){ //TODO use external file; FileInputStream fin = new FileInputStream(storename) ) {
			ks.load(in, storepass);
			return ks;
		} catch (FileNotFoundException e) {
			log.error("Anchor Key Store file not found, is it at " + storename, e);
			return null;
		} 

	}

	public List<X509Certificate> parseSignature(String in, boolean allowExpired){
		return parseSignature(new ByteArrayInputStream(in.getBytes()), allowExpired );
	}

	public List<X509Certificate> parseSignature(InputStream in, boolean allowExpired){
		List<X509Certificate> signingCerts = new ArrayList<>();
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(in);
			NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if(nl.getLength() == 0) {
				log.warn("Signature not present");
				return signingCerts;
			}
			for(int i = 0; i < nl.getLength(); i++) {
				XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
				X509KeySelector selector = new X509KeySelector(allowExpired);
				Node signatureNode = nl.item(i);
				DOMValidateContext valContext = new DOMValidateContext(selector, signatureNode);
				XMLSignature signature = fac.unmarshalXMLSignature(valContext);
				
				if(	signatureNode.getParentNode() != null &&
						WSSecurityBinarySecurityToken.WSSE_NAMESPACE.equals(
						signatureNode.getParentNode().getNamespaceURI()) &&
						WSSecurityBinarySecurityToken.SECURITY_NAME.equals(
								signatureNode.getParentNode().getLocalName() )  ){
					valContext.setURIDereferencer(createURIDereferencer(valContext.getURIDereferencer()));
				}

				boolean coreValidity = signature.validate(valContext);
				if (coreValidity == false) {
					log.warn("Signature " + i + " failed core validation");
					boolean sv = signature.getSignatureValue().validate(valContext);
					log.warn("Signature " + i + " " + 
							Base64.getEncoder().encodeToString(signature.getSignatureValue().getValue() ) + 
							" validation status: " + sv);

					@SuppressWarnings("unchecked")
					Iterable<Reference> refs = () -> signature.getSignedInfo().getReferences().iterator();
					for(Reference r : refs) {
						boolean refValid = r.validate(valContext);
						log.warn("ref["+r.getId()+" " + r.getURI() + " " + 
								Base64.getEncoder().encodeToString(r.getDigestValue()) + 
								" ] validity status: " + refValid);
					}
					return new ArrayList<>();
				} else {
					//log.info("Signature " + i + " passed core validation");
					signingCerts.add(selector.getClientCertificate());
				}
			}
		}catch(Exception e) {
			log.error("", e);
			return new ArrayList<>();
		}
		return signingCerts;
	}

	private URIDereferencer createURIDereferencer(URIDereferencer uriDereferencer) {
		return new URIDereferencer() {
			private final URIDereferencer parentReferencer = uriDereferencer;
			@Override
			public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {
				if(context instanceof DOMValidateContext ) {
					DOMValidateContext domContext = (DOMValidateContext) context;
					Document doc = domContext.getNode(). getOwnerDocument();
					String localReference = formatUriToId( uriReference.getURI() );
					NodeList list = doc.getChildNodes();
					Node idNode = findWsuId(list, localReference);
					if(idNode != null){
						try {
							return new OctetStreamData(nodeToInputStream(idNode));
						} catch (TransformerException e) {
							log.warn("XML Document can not be transformed to InputStream", e);
						}
					}
				}
				if(parentReferencer != null) {
					return parentReferencer.dereference(uriReference, context);
				}
				throw new URIReferenceException("Can not find URI " + uriReference.getType() + " in the SOAP Body" );
			}
			
		};
	}
	
	private static InputStream nodeToInputStream(Node node) throws TransformerException {
	    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	    Result outputTarget = new StreamResult(outputStream);
	    Transformer t = TransformerFactory.newInstance().newTransformer();
	    t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
	    t.transform(new DOMSource(node), outputTarget);
	    return new ByteArrayInputStream(outputStream.toByteArray());
	}
	
	private static String formatUriToId(String URI) {
		if(URI != null && URI.startsWith("#")) {
			return URI.substring(1);
		}
		return null;
	}

	private static Node findWsuId(NodeList list, String referenceId) {
		int j = 0;
		for(Node referred = list.item(j); referred != null ; referred = list.item(++j) ){
			NamedNodeMap map = referred.getAttributes();
			if(map == null) {
				continue;
			}
			Node id = map.getNamedItemNS(WSSecurityBinarySecurityToken.WSU_NAMESPACE, "Id");
			if(id != null && referenceId.equals(id.getNodeValue())  ){
				return referred;
			}
		}
		j = 0;
		for(Node referred = list.item(j); referred != null ; referred = list.item(++j) ){
			Node candidate = findWsuId( referred.getChildNodes(), referenceId );
			if(candidate != null) {
				return candidate;
			}
		}
		return null;
	}

	private static class X509KeySelector extends KeySelector {
		private X509Certificate clientCertificate;
		private boolean allowExpired;
		public X509KeySelector(boolean allowExpired) {
			this.allowExpired = allowExpired;
		}
		public KeySelectorResult select(KeyInfo keyInfo,KeySelector.Purpose purpose,AlgorithmMethod method,XMLCryptoContext context) throws KeySelectorException {
			@SuppressWarnings("unchecked")
			Iterable<XMLStructure> ki = () -> keyInfo.getContent().iterator();
			for( XMLStructure info : ki) {
				KeySelectorResult result = null;
				if ( info instanceof X509Data ) {
					X509Data x509Data = (X509Data) info;
					@SuppressWarnings("unchecked")
					Iterable<?> xi = () -> x509Data.getContent().iterator();
					for (Object o : xi){
						if (!(o instanceof X509Certificate)) {
							continue;
						}
						result = checkCertificate(o, method);
					}
				}else if( info instanceof DOMStructure ) {
					DOMStructure structure = (DOMStructure) info;
					if( WSSecurityBinarySecurityToken.SECURITY_TOKEN_REFERENCE_LOCAL_NAME.equals( 
							structure.getNode().getLocalName() ) &&
							WSSecurityBinarySecurityToken.WSSE_NAMESPACE.equals(
									structure.getNode().getNamespaceURI())  ){
						X509Certificate cert = followReference(structure.getNode() );
						result = checkCertificate(cert, method);
					}
				}
				if(result != null) {
					return result;
				}
			}
			throw new KeySelectorException("No key found!");
		}

		private X509Certificate followReference(Node node) {
			if(node == null) {
				return null;
			}

			if( WSSecurityBinarySecurityToken.BINARY_SECURITY_TOKEN_LOCAL_NAME.equals( 
					node.getLocalName() ) &&
					WSSecurityBinarySecurityToken.WSSE_NAMESPACE.equals(
							node.getNamespaceURI()) &&
					WSSecurityBinarySecurityToken.WSS_X509_TOKEN_PROFILE.equals(
							node.getAttributes().
							getNamedItem(WSSecurityBinarySecurityToken.VALUE_TYPE_ATTRIBUTE).getNodeValue() ) &&
					WSSecurityBinarySecurityToken.X509_ENCODING_TYPE.equals(
							node.getAttributes().
							getNamedItem(WSSecurityBinarySecurityToken.ENCODING_TYPE_ATTRIBUTE).getNodeValue())  ){

				return makeCertificate(node.getTextContent());
			}else if( "Reference".equals( 
					node.getLocalName() ) &&
					WSSecurityBinarySecurityToken.WSSE_NAMESPACE.equals(
							node.getNamespaceURI()) ) {

				String referenceId = formatUriToId( 
						node.getAttributes().getNamedItem("URI").getNodeValue() );
				NodeList list = node.getOwnerDocument().getElementsByTagNameNS(
						WSSecurityBinarySecurityToken.WSSE_NAMESPACE, 
						WSSecurityBinarySecurityToken.BINARY_SECURITY_TOKEN_LOCAL_NAME);
				
				Node referred = findWsuId(list, referenceId);
				if(referred != null ) {
					return followReference(referred);
				}
			}
			
			for(int i = 0; i < node.getChildNodes().getLength() ; i++ ) {
				Node child = node.getChildNodes().item(i);
				if(child == null ) {
					continue;
				}
				X509Certificate cert = followReference(child);
				if(cert != null ) {
					return cert;
				}
			}
			return null;
		}

		private X509Certificate makeCertificate(String nodeValue) {
			byte[] certBytes = Base64.getDecoder().decode(nodeValue);
			try(ByteArrayInputStream in = new ByteArrayInputStream(certBytes)){
				return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(in);
			} catch (CertificateException |IOException e) {
				log.warn("Corrupted Certificate", e );
			}
			return null;
		}
		public X509Certificate getClientCertificate() {
			return clientCertificate;
		}
		private KeySelectorResult checkCertificate(Object keyObject, AlgorithmMethod method) throws KeySelectorException {
			if(keyObject == null) {
				return null;
			}
			X509Certificate signingCert = (X509Certificate) keyObject;
			try {
				if( ! allowExpired ) {
					signingCert.checkValidity();
				}
				DigitalSignature.validateKeyChain(signingCert);
			} catch ( CertificateException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | CertPathValidatorException  e) {
				log.warn("Attached certificate is not valid", e);
				throw new KeySelectorException("Attached certificate is not valid");
			}
			final PublicKey key = signingCert.getPublicKey();
			// Make sure the algorithm is compatible
			// with the method.
			if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
				return () -> ( key);
			}
			return null;
		}

		boolean algEquals(String algURI, String algName) {
			if((algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) ||
					(algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1))) {
				return true;
			}else {
				return false;
			}
		}
	}

}


