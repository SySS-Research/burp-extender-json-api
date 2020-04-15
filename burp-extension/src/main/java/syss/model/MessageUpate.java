package syss.model;

import burp.IInterceptedProxyMessage;

import java.util.List;

/**
 * @author Torsten Lutz
 */
public class MessageUpate {

    public enum Actions {
        NO_ACTION,
        GET_BODY,
        ADD_PARAMETER,
        DEL_PARAMETER,
        UPDATE_PARAMETER,
        BUILD_HTTP_MESSAGE,
        REPLACE_REQUEST_RESPONSE,
        REPLACE_REQUEST_BODY,
        REPLACE_RESPONSE_BODY,
        UPDATE_REQUEST_HEADERS,
        BASE64_DECODE_BODY,
        SET_PAYLOAD,
        // proxylistener actions
        ACTION_DO_INTERCEPT,
        ACTION_DO_INTERCEPT_AND_REHOOK,
        ACTION_DONT_INTERCEPT,
        ACTION_DONT_INTERCEPT_AND_REHOOK,
        ACTION_DROP,
        ACTION_FOLLOW_RULES,
        ACTION_FOLLOW_RULES_AND_REHOOK
    }

    private Actions action;
    private List<String> headers;
    private byte[] body;
    private String paramName;
    private String paramValue;
    private byte paramType;

    public MessageUpate() {}

    public Actions getAction() {
        return this.action;
    }

    public void setAction(Actions action) {
        this.action = action;
    }

    public List<String> getHeaders() {
        return this.headers;
    }

    public void setHeaders(List<String> headers) {
        this.headers = headers;
    }

    public byte[] getBody() {
        return this.body;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    public String getParamName() {
        return this.paramName;
    }

    public void setParamName(String paramName) {
        this.paramName = paramName;
    }

    public String getParamValue() {
        return this.paramValue;
    }

    public void setParamValue(String paramValue) {
        this.paramValue = paramValue;
    }

    public byte getParamType() {
        return this.paramType;
    }

    public void setParamType(byte paramType) {
        this.paramType = paramType;
    }

}
