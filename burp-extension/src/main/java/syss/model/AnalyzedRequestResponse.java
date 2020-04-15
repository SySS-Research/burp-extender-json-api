package syss.model;

import burp.IRequestInfo;
import burp.IResponseInfo;

public class AnalyzedRequestResponse {

    private byte[] request;
    private byte[] response;
    private IRequestInfo analyzedRequest;
    private IResponseInfo analyzedResponse;

    public byte[] getRequest() {
        return request;
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

}
