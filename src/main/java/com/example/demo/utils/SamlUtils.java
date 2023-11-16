package com.example.demo.utils;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.security.impl.RandomIdentifierGenerationStrategy;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
public class SamlUtils {
    private static final Logger logger = LogManager.getLogger(SamlUtils.class);

    //SP keystore位置
    private final String keyStorePath = "c:\\cert\\sp.jks";
    //SP keystore密码
    private final String keyStorePassword = "sp";
    //SP 私钥Id
    private final String keyEntryId = "sp";
    //SP 私钥密码
    private final String keyPassword = "sp";
    // SP client ID
    private final String spEntityId = "my_client";
    //IdP的证书公钥，用于在验证SamlResponse签名，这个公钥可以从idp-metadata文件中获取到
    private final String idpPublicKeyPath = "c:\\cert\\keycloak.pem";
    //IdP的endpoint，比如登录、退出的时候请求用的URL，这个URL可以从idp-metadata文件中获取到
    private final String idpDestinationUrl = "http://localhost:8080/realms/TestRealm/protocol/saml";
    private Credential spCredential;
    private BasicX509Credential idpBasicX509Credential;
    private static final RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    public SamlUtils() throws SamlException {
        try {
            JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
            javaCryptoValidationInitializer.init();
            for (Provider jceProvider : Security.getProviders()) {
                logger.info(jceProvider.getInfo());
            }
            InitializationService.initialize();
            initSpCredential();
            initIdpCredential();
        } catch (Exception e) {
            throw new SamlException("Saml util initialization failed.", e);
        }
    }

    //签名URL：https://idp-endpoint?SAMLRequest=XXX&RelayState=XXX&SigAlg=xxx&Signature=XXX
    //不签名URL：https://idp-endpoint?SAMLRequest=XXX&RelayState=XXX
    public String getRedirectUrl(HttpServletResponse httpServletResponse, String relayState) throws SamlException {
        try {
            return buildRedirectUrl(httpServletResponse, relayState);
        } catch (Exception e) {
            throw new SamlException("Get redirect url error.", e);
        }
    }

    public String getNameID(String samlResponse) throws SamlException {
        Response response;
        try {
            response = decodeSAMLResponse(samlResponse);
        } catch (Exception e) {
            throw new SamlException("SAML response decode failed");
        }

        //Status
        Status responseStatus = response.getStatus();
        if (responseStatus == null || !StatusCode.SUCCESS.equals(responseStatus.getStatusCode().getValue())) {
            throw new SamlException("SAML response status is invalid");
        }

        //Assertions
        Assertion assertion = response.getAssertions().get(0);

        //Assertions - Signature
        verifyAssertionSignature(assertion);

        //Assertions - Conditions
        //also can verify Conditions

        return assertion.getSubject().getNameID().getValue();
    }

    private AuthnRequest buildAuthnRequest() throws NoSuchFieldException, IllegalAccessException {
        /*
            <?xml version="1.0" encoding="UTF-8"?>
            <saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_6aaa06ff4377c75b2e768fc0086e935c"
                IssueInstant="2023-11-11T03:10:19.299Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">
                <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">my_client</saml2:Issuer>
                <saml2p:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />
                <saml2p:RequestedAuthnContext Comparison="minimum">
                    <saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" />
                </saml2p:RequestedAuthnContext>
            </saml2p:AuthnRequest>
         */
        //Build AuthnRequest（XML）Start
        AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class);

        //requestedAuthnContext
        RequestedAuthnContext requestedAuthnContext = buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        AuthnContextClassRef passwordAuthnContextClassRef = buildSAMLObject(AuthnContextClassRef.class);
        //passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);
        authnRequest.setRequestedAuthnContext(requestedAuthnContext);

        //IssueInstant
        authnRequest.setIssueInstant(Instant.now());

        //ProtocolBinding
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

        //Destination
        authnRequest.setDestination(idpDestinationUrl);

        //ID
        authnRequest.setID(secureRandomIdGenerator.generateIdentifier());

        //issuer
        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setValue(spEntityId);
        authnRequest.setIssuer(issuer);

        //NameIdPolicy
        NameIDPolicy nameIDPolicy = buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        authnRequest.setNameIDPolicy(nameIDPolicy);

        return authnRequest;
    }

    private MessageContext buildMessageContext(String relayState) throws NoSuchFieldException, IllegalAccessException {
        MessageContext context = new MessageContext();

        //context add authnRequest
        AuthnRequest authnRequest = buildAuthnRequest();
        context.setMessage(authnRequest);

        //context add endpoint
        SingleSignOnService endpoint = buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        endpoint.setLocation(idpDestinationUrl);
        context.getSubcontext(SAMLPeerEntityContext.class, true)
                .getSubcontext(SAMLEndpointContext.class, true)
                .setEndpoint(endpoint);

        //context add SignatureSigningParameters
        if (spCredential != null) {
            SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSigningCredential(spCredential);
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            context.getSubcontext(SecurityParametersContext.class, true)
                    .setSignatureSigningParameters(signatureSigningParameters);
        }

        //context add RelayState
        context.getSubcontext(SAMLBindingContext.class, true)
                .setRelayState(relayState);

        return context;
    }

    private String buildRedirectUrl(HttpServletResponse httpServletResponse, String relayState) throws ComponentInitializationException, MessageEncodingException, SamlException {
        SAMLHTTPRedirectDeflateEncoder encoder = new SAMLHTTPRedirectDeflateEncoder();
        try {
            encoder.setMessageContext(buildMessageContext(relayState));
        } catch (Exception e) {
            throw new SamlException("Build MessageContext failed", e);
        }
        encoder.setHttpServletResponse(httpServletResponse);
        encoder.initialize();

        return encoder.buildEncodedRedirectUrl();
    }

    private void initSpCredential() throws ResolverException, IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore;
        try (InputStream inputStream = new FileInputStream(keyStorePath)) {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(inputStream, keyStorePassword.toCharArray());
        }

        Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put(keyEntryId, keyPassword);
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

        Criterion criterion = new EntityIdCriterion(keyEntryId);
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(criterion);

        spCredential = resolver.resolveSingle(criteriaSet);
    }

    private void initIdpCredential() throws IOException, CertificateException {
        try (InputStream inputStream = new FileInputStream(idpPublicKeyPath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(inputStream);
            idpBasicX509Credential = CredentialSupport.getSimpleCredential(cert, null);
        }
    }

    private void verifyAssertionSignature(Assertion assertion) throws SamlException {
        if (idpBasicX509Credential == null) {
            return;
        }

        if (!assertion.isSigned()) {
            throw new SamlException("The SAML assertion was not signed");
        }
        try {

            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());
            SignatureValidator.validate(assertion.getSignature(), idpBasicX509Credential);
        } catch (Exception e) {
            throw new SamlException("The SAML assertion signature is invalid");
        }
    }

    private Response decodeSAMLResponse(String samlResponse) throws
            ParserConfigurationException, IOException, SAXException, UnmarshallingException {
        UnmarshallerFactory unmarshallerFactory = null;
        DocumentBuilder docBuilder = null;
        byte[] base64DecodedResponse = Base64.decodeBase64(samlResponse);
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl");
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        documentBuilderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        documentBuilderFactory.setNamespaceAware(true);
        docBuilder = documentBuilderFactory.newDocumentBuilder();
        unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();

        Document document = docBuilder.parse(new ByteArrayInputStream(base64DecodedResponse));

        Element element = document.getDocumentElement();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        XMLObject responseXmlObj = unmarshaller.unmarshall(element);

        return (Response) responseXmlObj;
    }

    private <T> T buildSAMLObject(final Class<T> clazz) throws NoSuchFieldException, IllegalAccessException {
        T object = null;

        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);

        return object;
    }

    private static class SAMLHTTPRedirectDeflateEncoder extends HTTPRedirectDeflateEncoder {
        public String buildEncodedRedirectUrl() throws MessageEncodingException {
            //context
            MessageContext messageContext = getMessageContext();

            //deflate and base64 encode
            SAMLObject outboundMessage = (SAMLObject) messageContext.getMessage();
            removeSignature(outboundMessage);
            String encodedMessage = deflateAndBase64Encode(outboundMessage);

            //endpoint
            String endpointURL = getEndpointURL(messageContext).toString();

            return buildRedirectURL(messageContext, endpointURL, encodedMessage);
        }
    }
}