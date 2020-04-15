package syss.model;

import burp.IRequestInfo;
import burp.IResponseInfo;

public class AnalyzedMessage {

    private int toolFlag;
    private byte[] request;
    private byte[] response;
    private IRequestInfo analyzedRequest;
    private IResponseInfo analyzedResponse;

    public int getToolFlag() {
        return this.toolFlag;
    }

    public void setToolFlag(int toolFlag) {
        this.toolFlag = toolFlag;
    }

    public IResponseInfo getAnalyzedResponse() {
        return this.analyzedResponse;
    }

    public void setAnalyzedResponse(IResponseInfo analyzedResponse) {
        this.analyzedResponse = analyzedResponse;
    }

    public IRequestInfo getAnalyzedRequest() {
        return this.analyzedRequest;
    }

    public void setAnalyzedRequest(IRequestInfo analyzedRequest) {
        this.analyzedRequest = analyzedRequest;
    }

    public byte[] getRequest() {
        return this.request;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    public byte[] getResponse() {
        return response;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }
}
