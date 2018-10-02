package com.vdenotaris.spring.boot.security.saml.web.bindings;

import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPArtifactDecoderImpl;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLBindingImpl;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.thymeleaf.TemplateEngine;

import java.util.List;

public class HTTPArtifactBindingThymeleaf extends SAMLBindingImpl {

    /**
     * Creates default implementation of the binding.
     *
     * @param parserPool      parserPool for message deserialization
     * @param thymeleafEngine  engine for message formatting
     * @param artifactProfile profile used to retrieven the artifact message
     */
    public HTTPArtifactBindingThymeleaf(ParserPool parserPool, TemplateEngine thymeleafEngine, ArtifactResolutionProfile artifactProfile) {
        this(new HTTPArtifactDecoderImpl(artifactProfile, parserPool), new HTTPArtifactEncoderThymeleaf(thymeleafEngine, "/templates/saml2-post-artifact-binding.html", null));
    }

    /**
     * Implementation of the binding with custom encoder and decoder.
     *
     * @param decoder custom decoder implementation
     * @param encoder custom encoder implementation
     */
    public HTTPArtifactBindingThymeleaf(MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
    }

    public boolean supports(InTransport transport) {
        if (transport instanceof HTTPInTransport) {
            HTTPInTransport t = (HTTPInTransport) transport;
            return t.getParameterValue("SAMLart") != null;
        } else {
            return false;
        }
    }

    public boolean supports(OutTransport transport) {
        return transport instanceof HTTPOutTransport;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

        SignatureTrustEngine engine = samlContext.getLocalTrustEngine();
        securityPolicy.add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(engine));

    }
}
