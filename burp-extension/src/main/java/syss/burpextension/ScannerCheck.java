package syss.burpextension;

import burp.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.model.AnalyzedMessage;
import syss.model.MessageUpate;
import syss.model.ScanIssue;
import syss.model.ScannerCheckConfigResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Torsten Lutz
 */
public class ScannerCheck extends SySSBurpExtension implements IScannerCheck {

    private ScannerCheckConfigResponse config;

    public ScannerCheck(IBurpExtenderCallbacks burpCallbacks, String callbackUrl) {
        super(burpCallbacks, callbackUrl);
        this.initConfig();
    }

    private void initConfig() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.callbackUrl, mapper.writeValueAsString(""), this.logEnabled);

            this.config = mapper.readValue(responseStr, ScannerCheckConfigResponse.class);
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> result = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();
        try {
            AnalyzedMessage analyzedMessage = new AnalyzedMessage();
            //analyzedMessage.setToolFlag();
            analyzedMessage.setAnalyzedRequest(this.burpHelpers.analyzeRequest(baseRequestResponse));
            analyzedMessage.setRequest(baseRequestResponse.getRequest());
            analyzedMessage.setAnalyzedResponse(this.burpHelpers.analyzeResponse(baseRequestResponse.getResponse()));
            analyzedMessage.setResponse(baseRequestResponse.getResponse());

            String responseStr = this.httpClient.doPostJsonRequest(
                    this.config.getPassiveScanCallbackUrl(),
                    mapper.writeValueAsString(analyzedMessage), this.logEnabled);
            result = mapper.readValue(responseStr, new TypeReference<List<ScanIssue>>() {});
            for (IScanIssue issue : result) {
                ((ScanIssue)issue).setHttpService(baseRequestResponse.getHttpService());
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        int result = 0;
        ObjectMapper mapper = new ObjectMapper();
        try {
            Map<String, IScanIssue> issues = new HashMap<>();
            issues.put("existingIssue", existingIssue);
            issues.put("newIssue", newIssue);
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.config.getConsolidateDuplicateCallbackUrl(),
                    mapper.writeValueAsString(issues), this.logEnabled);
            result = mapper.readValue(responseStr, new TypeReference<Integer>() {});
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @Override
    public void register() {
        this.burpCallbacks.registerScannerCheck(this);
    }

    @Override
    public void unRegister() {
        this.burpCallbacks.removeScannerCheck(this);
    }
}
