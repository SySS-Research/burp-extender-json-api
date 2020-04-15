package syss.model;

/**
 * @author Torsten Lutz
 */
public class MessageEditorGetConfigResponse {

    private String caption;
    private String setMessageCallbackUrl;
    private String getMessageCallbackUrl;
    private boolean editable = false;
    private boolean cacheEnabled = true;

    public String getCaption() {
        return this.caption;
    }

    public void setCaption(String caption) {
        this.caption = caption;
    }

    public String getSetMessageCallbackUrl() {
        return this.setMessageCallbackUrl;
    }

    public void setSetMessageCallbackUrl(String setMessageCallbackUrl) {
        this.setMessageCallbackUrl = setMessageCallbackUrl;
    }

    public String getGetMessageCallbackUrl() {
        return this.getMessageCallbackUrl;
    }

    public void setGetMessageCallbackUrl(String getMessageCallbackUrl) {
        this.getMessageCallbackUrl = getMessageCallbackUrl;
    }

    public boolean isEditable() {
        return this.editable;
    }

    public void setEditable(boolean editable) {
        this.editable = editable;
    }

    public boolean isCacheEnabled() {
        return this.cacheEnabled;
    }

    public void setCacheEnabled(boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }
}
