package syss.model;

import burp.IInterceptedProxyMessage;
import burp.IRequestInfo;
import burp.IResponseInfo;

/**
 * @author Torsten Lutz
 */
public class InterceptedMessage {

    private IInterceptedProxyMessage message;
    private IRequestInfo analyzedRequest;
    private IResponseInfo analyzedResponse;

    public IInterceptedProxyMessage getMessage() {
        return this.message;
    }

    public void setMessage(IInterceptedProxyMessage message) {
        this.message = message;
    }

    public IRequestInfo getAnalyzedRequest() {
        return this.analyzedRequest;
    }

    public void setAnalyzedRequest(IRequestInfo analyzedRequest) {
        this.analyzedRequest = analyzedRequest;
    }

    public IResponseInfo getAnalyzedResponse() {
        return this.analyzedResponse;
    }

    public void setAnalyzedResponse(IResponseInfo analyzedResponse) {
        this.analyzedResponse = analyzedResponse;
    }
}
