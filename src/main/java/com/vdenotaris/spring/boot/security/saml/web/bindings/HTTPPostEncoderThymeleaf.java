package com.vdenotaris.spring.boot.security.saml.web.bindings;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.BaseSAML2MessageEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

public class HTTPPostEncoderThymeleaf extends BaseSAML2MessageEncoder {

    /**
     * Class logger.
     */
    private final Logger log = LoggerFactory.getLogger(HTTPPostEncoder.class);

    /**
     * Thymeleaf engine used to evaluate the template when performing POST encoding.
     */
    private TemplateEngine templateEngine;

    /**
     * ID of the Thymeleaf template used when performing POST encoding.
     */
    private String thymeleafTemplateId;

    /**
     * Constructor.
     *
     * @param engine     Thymeleaf engine instance used to create POST body
     * @param templateId ID of the template used to create POST body
     */
    public HTTPPostEncoderThymeleaf(TemplateEngine engine, String templateId) {
        super();
        templateEngine = engine;
        thymeleafTemplateId = templateId;
    }

    /**
     * {@inheritDoc}
     */
    public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    /**
     * {@inheritDoc}
     */
    public boolean providesMessageConfidentiality(MessageContext messageContext) throws MessageEncodingException {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public boolean providesMessageIntegrity(MessageContext messageContext) throws MessageEncodingException {
        return false;
    }

    /**
     * {@inheritDoc}
     */
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

        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

        SAMLObject outboundMessage = samlMsgCtx.getOutboundSAMLMessage();
        if (outboundMessage == null) {
            throw new MessageEncodingException("No outbound SAML message contained in message context");
        }
        String endpointURL = getEndpointURL(samlMsgCtx).buildURL();

        if (samlMsgCtx.getOutboundSAMLMessage() instanceof StatusResponseType) {
            ((StatusResponseType) samlMsgCtx.getOutboundSAMLMessage()).setDestination(endpointURL);
        }

        signMessage(samlMsgCtx);
        samlMsgCtx.setOutboundMessage(outboundMessage);

        postEncode(samlMsgCtx, endpointURL);
    }

    /**
     * Base64 and POST encodes the outbound message and writes it to the outbound transport.
     *
     * @param messageContext current message context
     * @param endpointURL    endpoint URL to which to encode message
     * @throws MessageEncodingException thrown if there is a problem encoding the message
     */
    protected void postEncode(SAMLMessageContext messageContext, String endpointURL) throws MessageEncodingException {
        log.debug("Invoking Thymeleaf template to create POST body");
        try {
            Context context = new Context();
            populatehymeleafContext(context, messageContext, endpointURL);

            HTTPOutTransport outTransport = (HTTPOutTransport) messageContext.getOutboundMessageTransport();
            HTTPTransportUtils.addNoCacheHeaders(outTransport);
            HTTPTransportUtils.setUTF8Encoding(outTransport);
            HTTPTransportUtils.setContentType(outTransport, "text/html");

            Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
            templateEngine.process(thymeleafTemplateId, context, out);
            out.flush();
        } catch (Exception e) {
            log.error("Error invoking Thymeleaf template", e);
            throw new MessageEncodingException("Error creating output document", e);
        }
    }

    /**
     * Populate the Thymeleaf context instance which will be used to render the POST body.
     *
     * @param thymeleafContext the Thymeleaf context instance to populate with data
     * @param messageContext   the SAML message context source of data
     * @param endpointURL      endpoint URL to which to encode message
     * @throws MessageEncodingException thrown if there is a problem encoding the message
     */
    protected void populatehymeleafContext(Context thymeleafContext, SAMLMessageContext messageContext,
                                           String endpointURL) throws MessageEncodingException {

        Encoder esapiEncoder = ESAPI.encoder();

        String encodedEndpointURL = esapiEncoder.encodeForHTMLAttribute(endpointURL);
        log.debug("Encoding action url of '{}' with encoded value '{}'", endpointURL, encodedEndpointURL);
        thymeleafContext.setVariable("action", encodedEndpointURL);
        thymeleafContext.setVariable("binding", getBindingURI());

        log.debug("Marshalling and Base64 encoding SAML message");
        if (messageContext.getOutboundSAMLMessage().getDOM() == null) {
            marshallMessage(messageContext.getOutboundSAMLMessage());
        }
        try {
            String messageXML = XMLHelper.nodeToString(messageContext.getOutboundSAMLMessage().getDOM());
            String encodedMessage = Base64.encodeBytes(messageXML.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
            if (messageContext.getOutboundSAMLMessage() instanceof RequestAbstractType) {
                thymeleafContext.setVariable("SAMLRequest", encodedMessage);
            } else if (messageContext.getOutboundSAMLMessage() instanceof StatusResponseType) {
                thymeleafContext.setVariable("SAMLResponse", encodedMessage);
            } else {
                throw new MessageEncodingException(
                        "SAML message is neither a SAML RequestAbstractType or StatusResponseType");
            }
        } catch (UnsupportedEncodingException e) {
            log.error("UTF-8 encoding is not supported, this VM is not Java compliant.");
            throw new MessageEncodingException("Unable to encode message, UTF-8 encoding is not supported");
        }

        String relayState = messageContext.getRelayState();
        if (checkRelayState(relayState)) {
            String encodedRelayState = esapiEncoder.encodeForHTMLAttribute(relayState);
            log.debug("Setting RelayState parameter to: '{}', encoded as '{}'", relayState, encodedRelayState);
            thymeleafContext.setVariable("RelayState", encodedRelayState);
        }
    }
}
