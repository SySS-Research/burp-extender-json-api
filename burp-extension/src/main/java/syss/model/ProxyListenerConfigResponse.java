package syss.model;

public class ProxyListenerConfigResponse {

    private boolean handleRequest;
    private boolean handleResponse;
    private String processMsgCallbackUrl;

    public boolean isHandleRequest() {
        return handleRequest;
    }

    public void setHandleRequest(boolean handleRequest) {
        this.handleRequest = handleRequest;
    }

    public boolean isHandleResponse() {
        return handleResponse;
    }

    public void setHandleResponse(boolean handleResponse) {
        this.handleResponse = handleResponse;
    }

    public String getProcessMsgCallbackUrl() {
        return processMsgCallbackUrl;
    }

    public void setProcessMsgCallbackUrl(String processMsgCallbackUrl) {
        this.processMsgCallbackUrl = processMsgCallbackUrl;
    }
}
