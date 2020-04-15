package syss.model;

import burp.IHttpRequestResponse;

public class ProxyHistoryResponse {

    IHttpRequestResponse[] history;

    public IHttpRequestResponse[] getHistory() {
        return history;
    }

    public void setHistory(IHttpRequestResponse[] history) {
        this.history = history;
    }
}
