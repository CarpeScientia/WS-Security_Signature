package local.cs.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.TreeSet;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;


public class WSSecurityHandler implements SOAPHandler<SOAPMessageContext> {

	private String login;
	private String pwd;
	private PassWordType passWordType;
	private static final String WSSE_PREFIX = "wsse";
	private static final String WSSE_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	private static final boolean debug = true;

	public enum PassWordType{
		PasswordDigest("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"),
		PasswordText("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"),
		Empty("");
		final String typeValue;
		private PassWordType(String typeValue) {this.typeValue = typeValue;}
	}
	
	public WSSecurityHandler(String login, String pwd) {
		this.login = login;
		this.pwd = pwd;
	}
	
	public WSSecurityHandler(String login, String pwd, PassWordType passWordType) {
		this.login = login;
		this.pwd = pwd;
		this.passWordType = passWordType;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		
		if (outboundProperty.booleanValue()) {
			try {
				// outgoing message
				SOAPEnvelope envelope = context.getMessage().getSOAPPart().getEnvelope();
				SOAPFactory factory = SOAPFactory.newInstance();

				SOAPElement securityElem = factory.createElement("Security", WSSE_PREFIX, WSSE_NAMESPACE);
				SOAPElement tokenElem = factory.createElement("UsernameToken", WSSE_PREFIX, WSSE_NAMESPACE);
				
				addUserNameAndPassword(factory, tokenElem);
				securityElem.addChildElement(tokenElem);
				SOAPHeader header = envelope.getHeader();
				if(header == null) {
					header = envelope.addHeader();
				}
				header.addChildElement(securityElem);
				
				context.getMessage().saveChanges();
			} catch (Exception e) {
				e.printStackTrace();
			}
		
		}
		if(debug) {
			System.out.println("Address of Endpoint " + context.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY));

			printSoapBody(context.getMessage());
		}
		return true;
	}

	private void addUserNameAndPassword(SOAPFactory factory, SOAPElement tokenElem)
			throws SOAPException {
		SOAPElement userElem = factory.createElement("Username", WSSE_PREFIX, WSSE_NAMESPACE);
		userElem.addTextNode(login);
		SOAPElement pwdElem = factory.createElement("Password", WSSE_PREFIX, WSSE_NAMESPACE);
		pwdElem.addTextNode(pwd);
		if(passWordType != null) {
			pwdElem.addAttribute(QName.valueOf("Type"), passWordType.typeValue);
		}
		tokenElem.addChildElement(userElem);
		tokenElem.addChildElement(pwdElem);
	}
	
	public static void printSoapBody(SOAPMessage msg) {
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
}