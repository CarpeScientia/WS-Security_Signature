package local.cs.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class WSSecurityBinarySecurityToken implements SOAPHandler<SOAPMessageContext> {
	public static final String SECURITY_NAME = "Security";
	public static final String ENCODING_TYPE_ATTRIBUTE = "EncodingType";
	public static final String VALUE_TYPE_ATTRIBUTE = "ValueType";
	public static final String X509_ENCODING_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
	public static final String BINARY_SECURITY_TOKEN_LOCAL_NAME = "BinarySecurityToken";
	public static final String SECURITY_TOKEN_REFERENCE_LOCAL_NAME = "SecurityTokenReference";
	public static final String WSS_X509_TOKEN_PROFILE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
	public static final String WSSE_PREFIX = "wsse";
	public static final String WSSE_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	public static final String WSU_PREFIX = "wsu";
	public static final String  WSU_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	private static final boolean debug = true;
	
	private X509Certificate certificate;
	private KeyStore.PrivateKeyEntry keyEntry;
	
	public WSSecurityBinarySecurityToken(String keyAlias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, UnrecoverableEntryException, IOException {
		keyEntry = XmlSigner.loadKey(keyAlias);
		certificate = (X509Certificate) keyEntry.getCertificate();
	}

	private static final Logger log = LoggerFactory.getLogger(WSSecurityBinarySecurityToken.class);
	


	
	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		if (outboundProperty.booleanValue()) {
			try {
				// outgoing message
				String soapBodyReference = createHeader(context);
				SOAPEnvelope envelope = context.getMessage().getSOAPPart().getEnvelope();
				// soapFactory = SOAPFactory.newInstance();
				SOAPHeader header = envelope.getHeader();
				SOAPHeaderElement securityHeader = (SOAPHeaderElement) header.getChildElements(new QName(WSSE_NAMESPACE,SECURITY_NAME, WSSE_PREFIX )).next();//should be only one
				// Create a DOM XMLSignatureFactory that will be used to
				// generate the enveloped signature.
				XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");

				// Create a Reference to the enveloped document (in this case,
				// specify the SHA1 digest algorithm and
				// the EXCLUSIVE Transform.
				Reference reference = signatureFactory.newReference(
						"#" + soapBodyReference, //Uri
						signatureFactory.newDigestMethod(DigestMethod.SHA1, null), //DigestMethod
						Collections.singletonList (
								signatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, new ExcC14NParameterSpec() )), //Transform.ENVELOPED, (ExcC14NParameterSpec) null   CanonicalizationMethod.EXCLUSIVE, new ExcC14NParameterSpec()
						null, //type
						null); //id
				
				CanonicalizationMethod canonicalization  = signatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE,
						new ExcC14NParameterSpec(Collections.singletonList(envelope.getPrefix()) )  );

				// Create the SignedInfo.
				SignedInfo signedInfo = signatureFactory.newSignedInfo
				 (canonicalization,
				    signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
				     Collections.singletonList(reference));

				// Create the KeyInfo 
				BigInteger keyInfoId = certificate.getSerialNumber().add(BigInteger.ONE);
				KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
				
				Element securityTokenReference = header.getOwnerDocument().createElementNS(WSSE_NAMESPACE, SECURITY_TOKEN_REFERENCE_LOCAL_NAME);
				securityTokenReference.setPrefix(WSSE_PREFIX);
				securityTokenReference.setAttributeNS(WSU_NAMESPACE, "Id", "STR-" + keyInfoId.add(BigInteger.ONE).toString() );
				Element wsseReference = header.getOwnerDocument().createElementNS(WSSE_NAMESPACE, "Reference");//
				wsseReference.setPrefix(WSSE_PREFIX);
				wsseReference.setAttribute("URI", "#X509-" + certificate.getSerialNumber().toString() );
				wsseReference.setAttribute(VALUE_TYPE_ATTRIBUTE, WSS_X509_TOKEN_PROFILE );
				securityTokenReference.appendChild(wsseReference);

				//newKeyInfo(List keyInfoContent, String id)
				KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(new DOMStructure(securityTokenReference) ), "KI-" + keyInfoId.toString());
				
				// Create a DOMSignContext and specify the RSA PrivateKey and
				// location of the resulting XMLSignature's parent element.
				DOMSignContext dsc = new DOMSignContext
				    (keyEntry.getPrivateKey(), securityHeader);//

				// Create the XMLSignature, but don't sign it yet.
				XMLSignature signature = signatureFactory.newXMLSignature
						(signedInfo, 
						keyInfo,
						null,
						"SIG-112",
						null);
						//Collections.singletonList(soapBody), 
						//soapBodyReference, 
						//null);//(signedInfo, keyInfo);

				// Marshal, generate, and sign the enveloped signature.
				signature.sign(dsc);
/*				NodeList signatures = securityHeader.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
				log.info("Current signature:" + signatures.item(0).getTextContent() );
				log.info("Current hash:" + Base64.getEncoder().encodeToString(reference.getDigestValue() ) );
				String resigned = Base64.getEncoder().encodeToString(
						resign(reference.getDigestValue(),keyEntry.getPrivateKey() ));
				log.info("new     signature:" + resigned );
				signatures.item(0).setTextContent(resigned);*/
		        
				context.getMessage().saveChanges();
			} catch (Exception e) {
				log.error("WS header siging failed", e);
			}

		}
		if(debug) {
			System.out.println("Address of Endpoint " + context.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY));

			printSoap(context.getMessage());
		}
		return true;
	}
	
	private String createHeader(SOAPMessageContext context) throws Exception{
		String soapBodyReference = createBodyId(context.getMessage().getSOAPBody());
		
		SOAPEnvelope envelope = context.getMessage().getSOAPPart().getEnvelope();
		SOAPFactory soapFactory = SOAPFactory.newInstance();
		SOAPHeader header = envelope.getHeader();
		if(header == null) {
			header = envelope.addHeader();
		}
		QName securityQname =  new QName(WSSE_NAMESPACE,SECURITY_NAME, WSSE_PREFIX );  //QName(String namespaceURI, String localPart, String prefix)
		SOAPHeaderElement securityHeader = header.addHeaderElement(securityQname);
		securityHeader.setMustUnderstand(true);
		securityHeader.addNamespaceDeclaration(WSU_PREFIX, WSU_NAMESPACE);

		//createElement(String localName, String prefix, String uri)
		String BinarySecurityTokenId = "X509-" + certificate.getSerialNumber().toString();
		SOAPElement tokenElem = soapFactory.createElement(BINARY_SECURITY_TOKEN_LOCAL_NAME, WSSE_PREFIX, WSSE_NAMESPACE);
		tokenElem.addAttribute(soapFactory.createName(ENCODING_TYPE_ATTRIBUTE), X509_ENCODING_TYPE);
		tokenElem.addAttribute(soapFactory.createName(VALUE_TYPE_ATTRIBUTE), WSS_X509_TOKEN_PROFILE );
		tokenElem.addAttribute(new QName(WSU_NAMESPACE,  "Id", WSU_PREFIX), BinarySecurityTokenId );
		tokenElem.addTextNode(Base64.getEncoder().encodeToString(certificate.getEncoded()));
		
		securityHeader.addChildElement(tokenElem);
		header.addChildElement(securityHeader);
		
		context.getMessage().saveChanges();//we changed the soapBody as well
		//WSSecurityHandler.printSoapBody(context.getMessage() );
		ByteArrayOutputStream out =  new ByteArrayOutputStream();//java does not update the DOM properly so re-serialize it
		context.getMessage().writeTo(out);
		context.setMessage(readSOAPMessage(out.toByteArray()));
		return soapBodyReference;
	}
	
	private SOAPMessage readSOAPMessage(byte[] bytes) throws SOAPException {
		MessageFactory mf = MessageFactory.newInstance();
		  SOAPMessage message = mf.createMessage();
		  SOAPPart soapPart = message.getSOAPPart();
		  ByteArrayInputStream is = new ByteArrayInputStream(bytes);
		  soapPart.setContent(new StreamSource(is));
		  return message;
	}
	
	private void printSoap(SOAPMessage msg) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			msg.writeTo(out);
		} catch (SOAPException | IOException e) {
			e.printStackTrace();
		}
		String strMsg = new String(out.toByteArray(), StandardCharsets.UTF_8);
		System.out.println(strMsg);
		
	}

	@Override
	public Set<QName> getHeaders() {
		return new TreeSet<QName>();
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return false;
	}

	@Override
	public void close(MessageContext context) {}
	
	private static final Random random = new Random();
	
	private static String createBodyId(SOAPBody body) {
		String wsuId = body.getAttributeNS(WSU_NAMESPACE, "Id");
		if(wsuId == null || "".equals(wsuId)) {
			wsuId = "id-" + random.nextInt(1000);
			body.setAttributeNS(WSU_NAMESPACE, "Id", wsuId);
		}
		return wsuId;
	}

}
