package syss.model;

public class ScannerCheckConfigResponse {

    private String passiveScanCallbackUrl;
    private String activeScanCallbackUrl;
    private String consolidateDuplicateCallbackUrl;

    public String getPassiveScanCallbackUrl() {
        return passiveScanCallbackUrl;
    }

    public void setPassiveScanCallbackUrl(String passiveScanCallbackUrl) {
        this.passiveScanCallbackUrl = passiveScanCallbackUrl;
    }

    public String getActiveScanCallbackUrl() {
        return activeScanCallbackUrl;
    }

    public void setActiveScanCallbackUrl(String activeScanCallbackUrl) {
        this.activeScanCallbackUrl = activeScanCallbackUrl;
    }

    public String getConsolidateDuplicateCallbackUrl() {
        return consolidateDuplicateCallbackUrl;
    }

    public void setConsolidateDuplicateCallbackUrl(String consolidateDuplicateCallbackUrl) {
        this.consolidateDuplicateCallbackUrl = consolidateDuplicateCallbackUrl;
    }
}
