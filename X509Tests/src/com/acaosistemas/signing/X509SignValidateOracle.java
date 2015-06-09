/**
 * @author Anderson Bestetti
 * @version 1.0
 * @see http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html
 * @see http://www.java-tips.org/java-ee-tips/xml-digital-signature-api/using-the-java-xml-digital-signatur-2.html
 * @see http://www.xinotes.net/notes/note/751/
 * @see http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
 * Teste de assinatura de um arquivo XML com um certificado padrao X.509.
 **/
package com.acaosistemas.signing;

import com.acaosistemas.x509.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class X509SignValidateOracle {

    private static final String KEY_STORE_TYPE   = "JKS";
    private static final String KEY_STORE_NAME   = "resources/URHDesenv_test_cert_public.pem";
    private static final String KEY_STORE_PASS   = "universalrh";
    private static final String KEY_ALIAS        = "1";

    /**
	 * @param args
     * @throws Throwable 
	 */
	public static void main(String[] args) throws Throwable {
		if (args.length < 1) {
			usage();
			return;
		}
		
		String inputFile  = args[0];
		
		// Create a DOM XMLSignatureFactory that will be used to
		// generate the enveloped signature.
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		
		// Instantiate the document to be signed.
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		
		Document doc;
		try {
			doc = dbf.newDocumentBuilder().parse
			    (new FileInputStream(inputFile));
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (SAXException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		}

		// Load the KeyStore and get the signing key and certificate.
		KeyStore ks;
		try {
			ks = KeyStore.getInstance(KEY_STORE_TYPE);
		} catch (KeyStoreException e) {
			throw new RuntimeException(e);
		}
		try {
			ks.load(new FileInputStream(KEY_STORE_NAME), KEY_STORE_PASS.toCharArray());
			
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		// Find Signature element.
		NodeList nl =
		    doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		
		if (nl.getLength() == 0) {
		    throw new Exception("Cannot find Signature element");
		}
		
		// Create a DOMValidateContext and specify a KeySelector
		// and document context.
		DOMValidateContext valContext = new DOMValidateContext
		    (new X509KeySelector(ks), nl.item(0));

		// Unmarshal the XMLSignature.
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);

		// Validate the XMLSignature.
		boolean coreValidity = signature.validate(valContext);
		
		// Check core validation status.
		if (coreValidity == false) {
		    System.err.println("Signature failed core validation");
		    boolean sv = signature.getSignatureValue().validate(valContext);
		    System.out.println("signature validation status: " + sv);
		    if (sv == false) {
		        // Check the validation status of each Reference.
		        Iterator i = signature.getSignedInfo().getReferences().iterator();
		        for (int j=0; i.hasNext(); j++) {
		            boolean refValid = ((Reference) i.next()).validate(valContext);
		            System.out.println("ref["+j+"] validity status: " + refValid);
		        }
		    }
		} else {
		    System.out.println("Signature passed core validation");
		}
	}
	
	public static void usage() {
		System.out.println("Usage: java X509SignValidateOracle inputSignedXMLFile");

	}

}
