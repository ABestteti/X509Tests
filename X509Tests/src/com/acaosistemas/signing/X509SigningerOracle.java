/**
 * @author Anderson Bestetti
 * @version 1.0
 * @see http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html
 * @see http://www.java-tips.org/java-ee-tips/xml-digital-signature-api/using-the-java-xml-digital-signatur-2.html
 * @see http://www.xinotes.net/notes/note/751/
 * Teste de assinatura de um arquivo XML com um certificado padrao X.509.
 **/
package com.acaosistemas.signing;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class X509SigningerOracle {

    private static final String KEY_STORE_TYPE   = "JKS";
    private static final String KEY_STORE_NAME   = "resources/URHDesenv_test_cert.jks";
    private static final String KEY_STORE_PASS   = "universalrh";
    private static final String KEY_ALIAS        = "1";
	
	public static void main(String[] args) {
		if (args.length < 2) {
			usage();
			return;
		}
		
		String inputFile  = args[0];
		String outputFile = args[1];
		

		// Create a DOM XMLSignatureFactory that will be used to
		// generate the enveloped signature.
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		
		// Create a Reference to the enveloped document (in this case,
		// you are signing the whole document, so a URI of "" signifies
		// that, and also specify the SHA1 digest algorithm and
		// the ENVELOPED Transform.
		Reference ref;
		try {
			ref = fac.newReference
			 ("", fac.newDigestMethod(DigestMethod.SHA1, null),
			  Collections.singletonList
			   (fac.newTransform
			    (Transform.ENVELOPED, (TransformParameterSpec) null)),
			     null, null);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
		
		// Create the SignedInfo.
		SignedInfo si;
		try {
			si = fac.newSignedInfo
			 (fac.newCanonicalizationMethod
			  (CanonicalizationMethod.INCLUSIVE,
			   (C14NMethodParameterSpec) null),
			    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
			     Collections.singletonList(ref));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
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
		
		KeyStore.PrivateKeyEntry keyEntry;
		try {
			keyEntry =
			    (KeyStore.PrivateKeyEntry) ks.getEntry
			        (KEY_ALIAS, new KeyStore.PasswordProtection(KEY_STORE_PASS.toCharArray()));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (UnrecoverableEntryException e) {
			throw new RuntimeException(e);
		} catch (KeyStoreException e) {
			throw new RuntimeException(e);
		}
		X509Certificate cert = (X509Certificate) keyEntry.getCertificate();	
		
		// Create the KeyInfo containing the X509Data.
		KeyInfoFactory kif;
		kif = fac.getKeyInfoFactory();
		List x509Content = new ArrayList();
		x509Content.add(cert.getSubjectX500Principal().getName());
		x509Content.add(cert);
		X509Data xd = kif.newX509Data(x509Content);
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
		

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
		
		// Create a DOMSignContext and specify the RSA PrivateKey and
		// location of the resulting XMLSignature's parent element.
		DOMSignContext dsc = new DOMSignContext
		    (keyEntry.getPrivateKey(), doc.getDocumentElement());
		
		// Create the XMLSignature, but don't sign it yet.
		XMLSignature signature = fac.newXMLSignature(si, ki);
		
		// Marshal, generate, and sign the enveloped signature.
		try {
			signature.sign(dsc);
		} catch (MarshalException e) {
			throw new RuntimeException(e);
		} catch (XMLSignatureException e) {
			throw new RuntimeException(e);
		}
		
		// Output the resulting document.
		OutputStream os;
		try {
			os = new FileOutputStream(outputFile);
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		}
		TransformerFactory tf = TransformerFactory.newInstance();
		
		Transformer trans;
		try {
			trans = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		
		try {
			trans.transform(new DOMSource(doc), new StreamResult(os));
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static void usage() {
		System.out.println("Usage: java X509SignerOracle inputXMLFile outputXMLFile");
	}

}
