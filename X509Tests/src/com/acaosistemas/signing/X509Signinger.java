/**
 * @author Anderson Bestetti
 * @version 1.0
 * @see http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html
 * @see http://www.java-tips.org/java-ee-tips/xml-digital-signature-api/using-the-java-xml-digital-signatur-2.html
 * @see http://www.xinotes.net/notes/note/751/
 * Teste de assinatura de um arquivo XML com um certificado padrao X.509.
 * Criado repositorio no GITHub.
 * Altera��o na A��o Sistemas.
 * 
 */
package com.acaosistemas.signing;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class X509Signinger {

	enum SignatureType {SIGN_BY_ID, SIGN_BY_PATH, SIGN_WHOLE_DOCUMENT};
	
    private static final String KEY_STORE_TYPE   = "JKS";
    //private static final String KEY_STORE_NAME   = "mykeystore";
    private static final String KEY_STORE_NAME   = "resources/URHDesenv_test_cert.jks";
    private static final String KEY_STORE_PASS   = "universalrh";
    private static final String PRIVATE_KEY_PASS = "universalrh";
    private static final String KEY_ALIAS        = "1";

    private static final String PATH = "/WiBitNet";
    private static final String ID   = "acct";
        
	/**
	 * @param args
	 */
	@SuppressWarnings("resource")
	public static void main(String[] args) {
		if (args.length < 2) {
			usage();
			return;
		}
		
		String inputFile  = args[0];
		String outputFile = args[1];
		SignatureType sigType = SignatureType.SIGN_WHOLE_DOCUMENT;
		
		if (args.length >= 3) {
		    if ("id".equals(args[2])) {
			sigType = SignatureType.SIGN_BY_ID;
		    }
		    else if ("path".equals(args[2])) {
			sigType = SignatureType.SIGN_BY_PATH;
		    }
		}
		
		// Instantiate the document to be signed
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		Document doc;
		try {
			 doc = dbFactory.newDocumentBuilder().parse(new FileInputStream(inputFile));
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (SAXException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		}
		
		// Prepare signature factory
		String providerName = System.getProperty("jsr105Provider","org.jcp.xml.dsig.internal.dom.XMLDSigRI");
		final XMLSignatureFactory sigFactory;
		try {
			sigFactory = XMLSignatureFactory.getInstance("DOM",(Provider) Class.forName(providerName).newInstance());
		} catch (InstantiationException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		} catch (ClassNotFoundException e) {
			throw new RuntimeException(e);
		}

		Node nodeToSign = null;
		Node sigParent = null;
		String referenceURI = null;
		XPathExpression expr = null; 
		NodeList nodes;
		List transforms = null;
		
		XPathFactory factory = XPathFactory.newInstance();
		XPath xpath = factory.newXPath();
		
		switch (sigType) {
		case SIGN_BY_ID:
			try {
				expr = xpath.compile(String.format("//*[@id='%s']", ID));
			} catch (XPathExpressionException e) {
				throw new RuntimeException(e);
			}
			try {
				nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			} catch (XPathExpressionException e) {
				throw new RuntimeException(e);
			}
			if (nodes.getLength() == 0) {
				System.out.println("Can't find node with id: " + ID);
				return;
			}

			nodeToSign = nodes.item(0);
			sigParent = nodeToSign.getParentNode();
			referenceURI = "#" + ID;
			break;
		case SIGN_BY_PATH:
			// Find the node to be signed by PATH
			try {
				expr = xpath.compile(PATH);
			} catch (XPathExpressionException e) {
				throw new RuntimeException(e);
			}
			try {
				nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			} catch (XPathExpressionException e) {
				throw new RuntimeException(e);
			}
			if (nodes.getLength() < 1) {
				System.out
						.println("Invalid document, can't find node by PATH: "
								+ PATH);
				return;
			}

			nodeToSign = nodes.item(0);
			sigParent = nodeToSign.getParentNode();
			referenceURI = ""; // Empty string means whole document
			try {
				transforms = new ArrayList<Transform>() {
					{
						add(sigFactory.newTransform(Transform.XPATH,
								new XPathFilterParameterSpec(PATH)));
						add(sigFactory.newTransform(Transform.ENVELOPED,
								(TransformParameterSpec) null));
					}
				};
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			} catch (InvalidAlgorithmParameterException e) {
				throw new RuntimeException(e);
			}

			break;
		default:
			sigParent = doc.getDocumentElement();
			referenceURI = ""; // Empty string means whole document
			try {
				transforms = Collections.singletonList(sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
				/*transforms = new ArrayList<Transform>() {
					{
						add(sigFactory.newTransform(Transform.ENVELOPED,
								(TransformParameterSpec) null));
						add(sigFactory.newTransform(Transform.BASE64,
								(TransformParameterSpec) null));
					}
				};*/
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			} catch (InvalidAlgorithmParameterException e) {
				throw new RuntimeException(e);
			}
			break;
		}
		
		// Retrieve signing key
		KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
		} catch (KeyStoreException e) {
			throw new RuntimeException(e);
		}
		try {
			keyStore.load(
			    new FileInputStream(KEY_STORE_NAME),  
			    KEY_STORE_PASS.toCharArray()
			);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		PrivateKey privateKey;
		try {
			privateKey = (PrivateKey) keyStore.getKey(
				    KEY_ALIAS,
				    PRIVATE_KEY_PASS.toCharArray()
				);
		} catch (UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		} catch (KeyStoreException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		
		X509Certificate cert;
		try {
			cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);			
		} catch (KeyStoreException e) {
			throw new RuntimeException(e);
		}
		PublicKey publicKey = cert.getPublicKey();
		
		// Create a Reference to the enveloped document
		Reference ref;
		try {
			ref = sigFactory.newReference(
					    referenceURI,
					    sigFactory.newDigestMethod(DigestMethod.SHA1, null),
					    transforms,
					    null, 
					    null
					);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
		
		// Create the SignedInfo
		SignedInfo signedInfo;
		try {
			signedInfo = sigFactory.newSignedInfo(
						    sigFactory.newCanonicalizationMethod(
							CanonicalizationMethod.INCLUSIVE, 
							(C14NMethodParameterSpec) null
						    ), 
						    sigFactory.newSignatureMethod(
							SignatureMethod.RSA_SHA1, 
							null
						    ),
						    Collections.singletonList(ref)
						);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
		
		// Create a KeyValue containing the RSA PublicKey 
		KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
		KeyValue keyValue;
	    try {
			keyValue = keyInfoFactory.newKeyValue(publicKey);
		} catch (KeyException e) {
			throw new RuntimeException(e);
		}
	    
        // Create a KeyInfo and add the KeyValue to it
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));
        
        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        DOMSignContext dsc = new DOMSignContext(privateKey, sigParent);
        
        // Create the XMLSignature (but don't sign it yet)
    	XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo);
    	
    	// Marshal, generate (and sign) the enveloped signature
        try {
			signature.sign(dsc);
		} catch (MarshalException e) {
			throw new RuntimeException(e);
		} catch (XMLSignatureException e) {
			throw new RuntimeException(e);
		}
        
        // output the resulting document
    	OutputStream os = null;
		try {
			os = new FileOutputStream(outputFile);
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		}
    	Transformer trans = null;
		try {
			trans = TransformerFactory.newInstance().newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		} catch (TransformerFactoryConfigurationError e) {
			throw new RuntimeException(e);
		}
    	try {
    		doc.normalizeDocument();
			trans.transform(new DOMSource(doc), new StreamResult(os));
			System.out.println("File "+outputFile+" created successfully.");
		} catch (TransformerException e) {
			System.out.println("Error when saving the file "+outputFile);
			throw new RuntimeException(e);
		}
        
	}
	
	private static void usage() {
		System.out.println("Usage: java X509Signer inputXMLFile outputXMLFile [id|path|whole]");
	}
}
