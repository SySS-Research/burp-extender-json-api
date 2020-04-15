package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.ISessionHandlingAction;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.MessageUpdateHandler;
import syss.model.AnalyzedMessage;
import syss.model.MessageUpate;
import syss.model.SessionHandlingActionRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SessionHandlingAction extends SySSBurpExtension implements ISessionHandlingAction {

    private String actionName;
    private String performCallbackUrl = null;

    public SessionHandlingAction(IBurpExtenderCallbacks burpCallbacks, String callbackUrl, String actionName) {
        super(burpCallbacks, callbackUrl);
        this.actionName = actionName;

        ObjectMapper mapper = new ObjectMapper();
        try {
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.callbackUrl, mapper.writeValueAsString(""), this.logEnabled);
            log.info(responseStr);
            HashMap<String, String> data = mapper.readValue(responseStr, new TypeReference<Map<String, String>>(){});
            this.performCallbackUrl = data.get("performCallbackUrl");
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    @Override
    public String getActionName() {
        return this.actionName;
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
//        if(null == this.performCallbackUrl) {
//            this.fetchConfig();
//        }

        ObjectMapper mapper = new ObjectMapper();
        try {
            // model to fill with all data
            SessionHandlingActionRequest data = new SessionHandlingActionRequest();

            // set analyzed request
            AnalyzedMessage crMsg = new AnalyzedMessage();
            crMsg.setAnalyzedRequest(this.burpHelpers.analyzeRequest(currentRequest));
            crMsg.setRequest(currentRequest.getRequest());
            data.setCurrentRequest(crMsg);

            // handle macro requests and responses
            List<AnalyzedMessage> macroList = new ArrayList<>();

            for (IHttpRequestResponse macro : macroItems) {
                AnalyzedMessage macroMsg = new AnalyzedMessage();
                macroMsg.setAnalyzedRequest(this.burpHelpers.analyzeRequest(macro));
                macroMsg.setRequest(macro.getRequest());
                macroMsg.setAnalyzedResponse(this.burpHelpers.analyzeResponse(macro.getResponse()));
                macroMsg.setResponse(macro.getResponse());
                macroList.add(macroMsg);
            }
            // add to data
            data.setMacroItems(macroList);
            // send data
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.performCallbackUrl, mapper.writeValueAsString(data), this.logEnabled);
            // map to objects
            List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>(){});
            // get update handler
            MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);
            // update the current request
            currentRequest.setRequest(handler.applyActions(updates, currentRequest.getRequest()));

        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    @Override
    public void register() {
        this.burpCallbacks.registerSessionHandlingAction(this);
    }

    @Override
    public void unRegister() {
        this.burpCallbacks.removeSessionHandlingAction(this);
    }
}
