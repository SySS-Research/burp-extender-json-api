package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.model.AnalyzedMessage;
import syss.model.GetInsertionPointsResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Torsten Lutz
 */
public class ScannerInsertionPointProvider extends SySSBurpExtension implements IScannerInsertionPointProvider {

    public ScannerInsertionPointProvider(final IBurpExtenderCallbacks callbacks, String callbackUrl) {
        super(callbacks, callbackUrl);
    }

    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
        List<IScannerInsertionPoint> resultList = new ArrayList<>();

        ObjectMapper mapper = new ObjectMapper();
        try {
            // set data to send via API
            AnalyzedMessage msg = new AnalyzedMessage();
            msg.setAnalyzedRequest(this.burpHelpers.analyzeRequest(baseRequestResponse));
            msg.setRequest(baseRequestResponse.getRequest());

            String responseStr = this.httpClient.doPostJsonRequest(
                    this.callbackUrl, mapper.writeValueAsString(msg), this.logEnabled);
            // map result
            GetInsertionPointsResponse data = mapper.readValue(responseStr, GetInsertionPointsResponse.class);

            for (String insertPointName : data.getInsertionPointNames()) {
                // create ScannerInsertionPoint objects
                IScannerInsertionPoint sip = new ScannerInsertionPoint(
                        this.burpCallbacks, data.getCallbackUrl(), baseRequestResponse, insertPointName);
                resultList.add(sip);
            }
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }

        return resultList;
    }

    public void register() {
        this.burpCallbacks.registerScannerInsertionPointProvider(this);
    }

    public void unRegister() {
        this.burpCallbacks.removeScannerInsertionPointProvider(this);
    }
}
