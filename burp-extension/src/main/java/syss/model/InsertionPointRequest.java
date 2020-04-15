package syss.model;

import burp.IRequestInfo;

/**
 * @author Torsten Lutz
 */
public class InsertionPointRequest {

    private byte[] request;
    private IRequestInfo analyzedRequest;
    private byte[] payload;
    String name;

    public InsertionPointRequest(){}

    public byte[] getRequest() {
        return this.request;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    public IRequestInfo getAnalyzedRequest() {
        return this.analyzedRequest;
    }

    public void setAnalyzedRequest(IRequestInfo analyzedRequest) {
        this.analyzedRequest = analyzedRequest;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
