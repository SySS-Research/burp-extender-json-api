package syss.model;

import java.util.List;

/**
 * @author Torsten Lutz
 */
public class GetInsertionPointsResponse {

    private String callbackUrl;
    private List<String> insertionPointNames;

    public GetInsertionPointsResponse() {}

    public String getCallbackUrl() {
        return this.callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public List<String> getInsertionPointNames() {
        return this.insertionPointNames;
    }

    public void setInsertionPointNames(List<String> insertionPointNames) {
        this.insertionPointNames = insertionPointNames;
    }
}
