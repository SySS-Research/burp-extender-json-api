package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.MessageUpdateHandler;
import syss.burpextension.SySSBurpExtension;
import syss.model.AnalyzedMessage;
import syss.model.HttpListenerConfigResponse;
import syss.model.MessageUpate;

import java.util.List;

/**
 * @author Torsten Lutz
 */
public class HttpListener extends SySSBurpExtension implements IHttpListener {

    private int restrictToolFlag = 0;
    private boolean handleRequest = false;
    private boolean handleResponse = false;
    private String processMsgCallbackUrl;

    public HttpListener(IBurpExtenderCallbacks burpCallbacks, String callbackUrl) {
        super(burpCallbacks, callbackUrl);
        this.initConfig();
    }

    private void initConfig() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.callbackUrl, mapper.writeValueAsString(""), this.logEnabled);

            HttpListenerConfigResponse config = mapper.readValue(responseStr, HttpListenerConfigResponse.class);
            this.restrictToolFlag = config.getToolFlag();
            this.handleRequest = config.isHandleRequest();
            this.handleResponse = config.isHandleResponse();
            this.processMsgCallbackUrl = config.getProcessMsgCallbackUrl();
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == (toolFlag & this.restrictToolFlag) &&
                ((messageIsRequest && this.handleRequest) || (!messageIsRequest && this.handleResponse))) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                AnalyzedMessage analyzedMessage = new AnalyzedMessage();
                analyzedMessage.setToolFlag(toolFlag);
                if (messageIsRequest) {
                    analyzedMessage.setAnalyzedRequest(this.burpHelpers.analyzeRequest(messageInfo));
                    analyzedMessage.setRequest(messageInfo.getRequest());
                } else {
                    analyzedMessage.setAnalyzedResponse(this.burpHelpers.analyzeResponse(messageInfo.getResponse()));
                    analyzedMessage.setResponse(messageInfo.getResponse());
                }

                String responseStr = this.httpClient.doPostJsonRequest(
                        this.processMsgCallbackUrl, mapper.writeValueAsString(analyzedMessage), this.logEnabled);

                List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>() {});
                MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);

                if (messageIsRequest) {
                    messageInfo.setRequest(handler.applyActions(updates, messageInfo.getRequest()));
                } else {
                    messageInfo.setResponse(handler.applyActions(updates, messageInfo.getResponse()));
                }

            } catch (Exception e) {
                e.printStackTrace(this.stderr);
            }
        }
    }

    @Override
    public void register() {
        this.burpCallbacks.registerHttpListener(this);
    }

    @Override
    public void unRegister() {
        this.burpCallbacks.removeHttpListener(this);
    }
}
