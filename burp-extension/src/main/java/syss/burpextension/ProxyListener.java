package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.MessageUpdateHandler;
import syss.burpextension.SySSBurpExtension;
import syss.model.InterceptedMessage;
import syss.model.MessageUpate;
import syss.model.ProxyListenerConfigResponse;

import java.util.List;

/**
 * @author Torsten Lutz
 */
public class ProxyListener extends SySSBurpExtension implements IProxyListener {

    private boolean handleRequest = false;
    private boolean handleResponse = false;
    private String processMsgCallbackUrl;

    public ProxyListener(IBurpExtenderCallbacks burpCallbacks, String callbackUrl) {
        super(burpCallbacks, callbackUrl);

        ObjectMapper mapper = new ObjectMapper();
        try {
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.callbackUrl, mapper.writeValueAsString(""), this.logEnabled);

            ProxyListenerConfigResponse config = mapper.readValue(responseStr, ProxyListenerConfigResponse.class);
            this.handleRequest = config.isHandleRequest();
            this.handleResponse = config.isHandleResponse();
            this.processMsgCallbackUrl = config.getProcessMsgCallbackUrl();
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if ((messageIsRequest && this.handleRequest) || (!messageIsRequest && this.handleResponse)) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                InterceptedMessage icm = new InterceptedMessage();
                icm.setMessage(message);
                if (messageIsRequest) {
                    icm.setAnalyzedRequest(this.burpHelpers.analyzeRequest(message.getMessageInfo()));
                } else {
                    icm.setAnalyzedResponse(
                            this.burpHelpers.analyzeResponse(message.getMessageInfo().getResponse()));
                }

                String responseStr = this.httpClient.doPostJsonRequest(
                        this.processMsgCallbackUrl, mapper.writeValueAsString(icm), this.logEnabled);

                List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>() {});
                MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);

                handler.applyActions(messageIsRequest, updates, message);

            } catch (Exception e) {
                e.printStackTrace(this.stderr);
            }
        }
    }

    @Override
    public void register() {
        this.burpCallbacks.registerProxyListener(this);
    }

    @Override
    public void unRegister() {
        this.burpCallbacks.removeProxyListener(this);
    }
}
