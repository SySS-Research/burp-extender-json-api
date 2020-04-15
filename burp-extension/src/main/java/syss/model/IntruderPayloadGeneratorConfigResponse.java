package syss.model;

/**
 * @author Torsten Lutz
 */
public class IntruderPayloadGeneratorConfigResponse {

    private String hasMorePayloadsCallbackUrl;
    private String getNextPayloadCallbackUrl;
    private String resetCallbackUrl;

    public String getHasMorePayloadsCallbackUrl() {
        return this.hasMorePayloadsCallbackUrl;
    }

    public void setHasMorePayloadsCallbackUrl(String hasMorePayloadsCallbackUrl) {
        this.hasMorePayloadsCallbackUrl = hasMorePayloadsCallbackUrl;
    }

    public String getGetNextPayloadCallbackUrl() {
        return this.getNextPayloadCallbackUrl;
    }

    public void setGetNextPayloadCallbackUrl(String getNextPayloadCallbackUrl) {
        this.getNextPayloadCallbackUrl = getNextPayloadCallbackUrl;
    }

    public String getResetCallbackUrl() {
        return this.resetCallbackUrl;
    }

    public void setResetCallbackUrl(String resetCallbackUrl) {
        this.resetCallbackUrl = resetCallbackUrl;
    }
}
