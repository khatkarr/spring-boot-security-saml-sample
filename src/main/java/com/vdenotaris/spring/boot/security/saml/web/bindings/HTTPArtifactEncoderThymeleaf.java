package com.vdenotaris.spring.boot.security.saml.web.bindings;

import org.opensaml.Configuration;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.AbstractSAMLArtifact;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.AbstractSAML2Artifact;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactBuilder;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.encoding.BaseSAML2MessageEncoder;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Pair;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.OutputStreamWriter;
import java.util.List;

public class HTTPArtifactEncoderThymeleaf extends BaseSAML2MessageEncoder {
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HTTPArtifactEncoder.class);

    /** Whether the POST encoding should be used, instead of GET. */
    private boolean postEncoding;

    /** thymeleaf engine used to evaluate the template when performing POST encoding. */
    private TemplateEngine thymeleafEngine;

    /** ID of the thymeleaf template used when performing POST encoding. */
    private String thymeleafTemplateId;

    /** SAML artifact map used to store created artifacts for later retrieval. */
    private SAMLArtifactMap artifactMap;

    /** Default artifact type to use when encoding messages. */
    private byte[] defaultArtifactType;

    /**
     * Constructor.
     *
     * @param engine thymeleaf engine used to construct the POST form
     * @param template ID of thymeleaf template used to construct the POST form
     * @param map artifact map used to store artifact/message bindings
     */
    public HTTPArtifactEncoderThymeleaf(TemplateEngine engine, String template, SAMLArtifactMap map) {
        super();
        postEncoding = false;
        thymeleafEngine = engine;
        thymeleafTemplateId = template;
        artifactMap = map;
        defaultArtifactType = SAML2ArtifactType0004.TYPE_CODE;
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }

    /**
     * Gets whether the encoder will encode the artifact via POST encoding.
     *
     * @return true if POST encoding will be used, false if GET encoding will be used
     */
    public boolean isPostEncoding() {
        return postEncoding;
    }

    /**
     * Sets whether the encoder will encode the artifact via POST encoding.
     *
     * @param post true if POST encoding will be used, false if GET encoding will be used
     */
    public void setPostEncoding(boolean post) {
        postEncoding = post;
    }

    /** {@inheritDoc} */
    public boolean providesMessageConfidentiality(MessageContext messageContext) throws MessageEncodingException {
        return false;
    }

    /** {@inheritDoc} */
    public boolean providesMessageIntegrity(MessageContext messageContext) throws MessageEncodingException {
        return false;
    }

    /** {@inheritDoc} */
    protected void doEncode(MessageContext messageContext) throws MessageEncodingException {
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Invalid message context type, this encoder only support SAMLMessageContext");
            throw new MessageEncodingException(
                    "Invalid message context type, this encoder only support SAMLMessageContext");
        }

        if (!(messageContext.getOutboundMessageTransport() instanceof HTTPOutTransport)) {
            log.error("Invalid outbound message transport type, this encoder only support HTTPOutTransport");
            throw new MessageEncodingException(
                    "Invalid outbound message transport type, this encoder only support HTTPOutTransport");
        }

        SAMLMessageContext artifactContext = (SAMLMessageContext) messageContext;
        HTTPOutTransport outTransport = (HTTPOutTransport) artifactContext.getOutboundMessageTransport();
        outTransport.setCharacterEncoding("UTF-8");

        if (postEncoding) {
            postEncode(artifactContext, outTransport);
        } else {
            getEncode(artifactContext, outTransport);
        }
    }

    /**
     * Performs HTTP POST based encoding.
     *
     * @param artifactContext current request context
     * @param outTransport outbound HTTP transport
     *
     * @throws MessageEncodingException thrown if there is a problem POST encoding the artifact
     */
    protected void postEncode(SAMLMessageContext artifactContext, HTTPOutTransport outTransport)
            throws MessageEncodingException {
        log.debug("Performing HTTP POST SAML 2 artifact encoding");

        log.debug("Creating thymeleaf context");
        Context context = new Context();
        Encoder esapiEncoder = ESAPI.encoder();
        String endpointURL = getEndpointURL(artifactContext).toString();
        String encodedEndpointURL = esapiEncoder.encodeForHTMLAttribute(endpointURL);
        log.debug("Setting action parameter to: '{}', encoded as '{}'", endpointURL, encodedEndpointURL);
        context.setVariable("action", encodedEndpointURL);
        context.setVariable("SAMLArt", buildArtifact(artifactContext).base64Encode());
        context.setVariable("binding", getBindingURI());

        if (checkRelayState(artifactContext.getRelayState())) {
            String encodedRelayState = esapiEncoder.encodeForHTMLAttribute(artifactContext.getRelayState());
            log.debug("Setting RelayState parameter to: '{}', encoded as '{}'", artifactContext.getRelayState(), encodedRelayState);
            context.setVariable("RelayState", encodedRelayState);
        }

        try {
            log.debug("Invoking thymeleaf template");
            OutputStreamWriter outWriter = new OutputStreamWriter(outTransport.getOutgoingStream());
            thymeleafEngine.process(thymeleafTemplateId, context, outWriter);
        } catch (Exception e) {
            log.error("Error invoking thymeleaf template to create POST form", e);
            throw new MessageEncodingException("Error creating output document", e);
        }
    }

    /**
     * Performs HTTP GET based encoding.
     *
     * @param artifactContext current request context
     * @param outTransport outbound HTTP transport
     *
     * @throws MessageEncodingException thrown if there is a problem GET encoding the artifact
     */
    protected void getEncode(SAMLMessageContext artifactContext, HTTPOutTransport outTransport)
            throws MessageEncodingException {
        log.debug("Performing HTTP GET SAML 2 artifact encoding");

        URLBuilder urlBuilder = getEndpointURL(artifactContext);

        List<Pair<String, String>> params = urlBuilder.getQueryParams();

        AbstractSAMLArtifact artifact = buildArtifact(artifactContext);
        if(artifact == null){
            log.error("Unable to build artifact for message to relying party");
            throw new MessageEncodingException("Unable to builder artifact for message to relying party");
        }
        params.add(new Pair<String, String>("SAMLart", artifact.base64Encode()));

        if (checkRelayState(artifactContext.getRelayState())) {
            params.add(new Pair<String, String>("RelayState", artifactContext.getRelayState()));
        }

        outTransport.sendRedirect(urlBuilder.buildURL());
    }

    /**
     * Builds the SAML 2 artifact for the outgoing message.
     *
     * @param artifactContext current request context
     *
     * @return SAML 2 artifact for outgoing message
     *
     * @throws MessageEncodingException thrown if the artifact can not be created
     */
    protected AbstractSAML2Artifact buildArtifact(SAMLMessageContext artifactContext) throws MessageEncodingException {

        SAML2ArtifactBuilder artifactBuilder;
        if (artifactContext.getOutboundMessageArtifactType() != null) {
            artifactBuilder = Configuration.getSAML2ArtifactBuilderFactory().getArtifactBuilder(
                    artifactContext.getOutboundMessageArtifactType());
        } else {
            artifactBuilder = Configuration.getSAML2ArtifactBuilderFactory().getArtifactBuilder(defaultArtifactType);
            artifactContext.setOutboundMessageArtifactType(defaultArtifactType);
        }

        AbstractSAML2Artifact artifact = artifactBuilder.buildArtifact(artifactContext);
        if(artifact == null){
            log.error("Unable to build artifact for message to relying party");
            throw new MessageEncodingException("Unable to builder artifact for message to relying party");
        }
        String encodedArtifact = artifact.base64Encode();
        try {
            artifactMap.put(encodedArtifact, artifactContext.getInboundMessageIssuer(), artifactContext
                    .getOutboundMessageIssuer(), artifactContext.getOutboundSAMLMessage());
        } catch (MarshallingException e) {
            log.error("Unable to marshall assertion to be represented as an artifact", e);
            throw new MessageEncodingException("Unable to marshall assertion to be represented as an artifact", e);
        }

        return artifact;
    }
}
