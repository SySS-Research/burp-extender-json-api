package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.MessageUpdateHandler;
import syss.burpextension.SySSBurpObject;
import syss.model.InsertionPointRequest;
import syss.model.MessageUpate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * @author Torsten Lutz
 */
public class ScannerInsertionPoint extends SySSBurpObject implements IScannerInsertionPoint {
    private final IHttpRequestResponse baseRequestResponse;
    private String baseValue = "";
    private String insertionPointName;
    private int[] payloadOffsets;

    public ScannerInsertionPoint(IBurpExtenderCallbacks burpCallbacks, String callbackUrl,
                                 IHttpRequestResponse baseRequestResponse, String insertionPointName) {
        super(burpCallbacks, callbackUrl);
        this.baseRequestResponse = baseRequestResponse;
        this.insertionPointName = insertionPointName;
    }

    @Override
    public String getInsertionPointName() {
        return this.insertionPointName;
    }

    @Override
    public String getBaseValue() {
        return this.baseValue;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        byte[] result = null;
        this.payloadOffsets = null;
        ObjectMapper mapper = new ObjectMapper();
        try {
            InsertionPointRequest ipr = new InsertionPointRequest();
            ipr.setRequest(this.baseRequestResponse.getRequest());
            ipr.setAnalyzedRequest(this.burpHelpers.analyzeRequest(this.baseRequestResponse));
            ipr.setPayload(payload);
            ipr.setName(this.insertionPointName);

            String responseStr = this.httpClient.doPostJsonRequest(this.callbackUrl, mapper.writeValueAsString(ipr));

            List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>(){});
            MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);

            if (updates.size() < 2) {
                if (1 == updates.size()) {
                    HashMap<byte[], int[]> requestAndOffsets = handler.applyActionSingle(
                            updates.get(0), this.baseRequestResponse.getRequest());
                    if (requestAndOffsets.size() > 0) {
                        Map.Entry<byte[], int[]> entry = requestAndOffsets.entrySet().iterator().next();
                        result = entry.getKey();
                        this.payloadOffsets = entry.getValue();
                    }
                } else {
                    this.stderr.println("Warning: Did not get any data to build payload for insertion point: " + this.insertionPointName);
                }
            } else {
                this.stderr.println("Warning: Message update size is incorrect for insertion point: " + this.insertionPointName);
            }

//            result = handler.applyActions(updates, result);

//            GetInsertionPointsResponse mydata = mapper.readValue(responseStr, GetInsertionPointsResponse.class);
//            result = this.burpHelpers.base64Decode(mydata.getRequest());
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }

        return result;

//        // TODO: request timeout does not seem to work
//        RequestConfig config = RequestConfig.custom()
//                .setConnectTimeout(1000)
//                .setConnectionRequestTimeout(2000)
//                .setSocketTimeout(2000)
//                .build();
//
//        HttpPost request = new HttpPost(this.callbackUrl);
//        request.setConfig(config);
//        ObjectMapper mapper = new ObjectMapper();
//        try {
//            InsertionPointRequest ipr = new InsertionPointRequest();
//            ipr.setModified(this.baseRequestResponse.getRequestResponse());
//            ipr.setAnalyzedRequest(this.burpHelpers.analyzeRequest(this.baseRequestResponse));
//
//            request.setEntity(new StringEntity(mapper.writeValueAsString(ipr), ContentType.APPLICATION_JSON));
//            log.info("Triggering request");
//            HttpResponse response = this.httpClient.execute(request);
//            log.info("Request done");
//            String responseStr = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
//            GetInsertionPointsResponse mydata = mapper.readValue(responseStr, GetInsertionPointsResponse.class);
//            result = Base64.getDecoder().decode(mydata.getRequestResponse());
//            log.info(this.burpHelpers.bytesToString(result));
//            //this.payloadOffsets =
//
//
//        } catch (NoHttpResponseException e) {
//            this.stderr.println("Got no response");
//        } catch (Exception e) {
//            e.printStackTrace(this.stderr);
//        }

        //IParameter param =  this.burpHelpers.getRequestParameter(this.baseRequestResponse.getRequestResponse(), "foo");
        //Parameter newParam = new Parameter(param.getName(), "gnaz", param.getNameStart(), param.getNameEnd(), param.getValueStart(), param.getValueEnd());

        //return this.burpHelpers.updateParameter(this.baseRequestResponse.getRequestResponse(), newParam);
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        return this.payloadOffsets;
    }

    @Override
    public byte getInsertionPointType() {
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
    }
}