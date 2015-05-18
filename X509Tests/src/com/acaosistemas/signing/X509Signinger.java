/**
 * 
 */
package com.acaosistemas.signing;

import javax.xml.crypto.dsig.XMLSignatureFactory;

/**
 * @author Anderson Bestetti
 * @version 1.0
 * 
 * Teste de assinatura de um arquivo XML com um certificado padrao X.509.
 * Criado repositorio no GITHub.
 * 01
 * 02
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
