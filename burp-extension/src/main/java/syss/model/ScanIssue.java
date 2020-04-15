package syss.model;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class ScanIssue implements IScanIssue {

    private String confidence;
    private IHttpRequestResponse[] httpMessages;
    private IHttpService httpService;
    private String issueBackground;
    private String issueDetail;
    private String issueName;
    private int issueType;
    private String remediationBackground;
    private String remediationDetail;
    private String severity;
    private URL url;

    @Override
    public String getConfidence() {
        return confidence;
    }

    public void setConfidence(String confidence) {
        this.confidence = confidence;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    public void setHttpMessages(IHttpRequestResponse[] httpMessages) {
        this.httpMessages = httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    public void setIssueBackground(String issueBackground) {
        this.issueBackground = issueBackground;
    }

    @Override
    public String getIssueDetail() {
        return issueDetail;
    }

    public void setIssueDetail(String issueDetail) {
        this.issueDetail = issueDetail;
    }

    @Override
    public String getIssueName() {
        return issueName;
    }

    public void setIssueName(String issueName) {
        this.issueName = issueName;
    }

    @Override
    public int getIssueType() {
        return issueType;
    }

    public void setIssueType(int issueType) {
        this.issueType = issueType;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    public void setRemediationBackground(String remediationBackground) {
        this.remediationBackground = remediationBackground;
    }

    @Override
    public String getRemediationDetail() {
        return remediationDetail;
    }

    public void setRemediationDetail(String remediationDetail) {
        this.remediationDetail = remediationDetail;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    public void setUrl(URL url) {
        this.url = url;
    }
}
