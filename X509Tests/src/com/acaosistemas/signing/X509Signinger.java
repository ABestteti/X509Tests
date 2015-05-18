/**
 * 
 */
package com.acaosistemas.signing;

import javax.xml.crypto.dsig.XMLSignatureFactory;

/**
 * @author Anderson Bestetti
 * @version 1.0
 * @see http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html
 * @see http://www.java-tips.org/java-ee-tips/xml-digital-signature-api/using-the-java-xml-digital-signatur-2.html
 * Teste de assinatura de um arquivo XML com um certificado padrao X.509.
 * Criado repositorio no GITHub.
 * 
 * 
 */
public class X509Signinger {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}
	
	public static void signXMLFile(String xmlToSign) {
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		fac = fac;
	}

}
