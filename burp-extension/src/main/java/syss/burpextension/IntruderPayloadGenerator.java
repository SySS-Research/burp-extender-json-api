package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.MessageUpdateHandler;
import syss.model.IntruderPayloadGeneratorConfigResponse;
import syss.model.MessageUpate;

import java.util.List;

/**
 * @author Torsten Lutz
 */
public class IntruderPayloadGenerator extends SySSBurpObject implements IIntruderPayloadGenerator {

    private String hasMorePayloadsCallbackUrl;
    private String getNextPayloadCallbackUrl;
    private String resetCallbackUrl;
    private IIntruderAttack attack;

    public IntruderPayloadGenerator(IBurpExtenderCallbacks burpCallbacks, String callbackUrl, IIntruderAttack attack) {
        super(burpCallbacks, callbackUrl);
        this.attack = attack;
        this.logEnabled = false;

        try {
            ObjectMapper mapper = new ObjectMapper();
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.callbackUrl, mapper.writeValueAsString(this.attack));
            IntruderPayloadGeneratorConfigResponse result = mapper.readValue(
                    responseStr, IntruderPayloadGeneratorConfigResponse.class);
            this.hasMorePayloadsCallbackUrl = result.getHasMorePayloadsCallbackUrl();
            this.getNextPayloadCallbackUrl = result.getGetNextPayloadCallbackUrl();
            this.resetCallbackUrl = result.getResetCallbackUrl();
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    @Override
    public boolean hasMorePayloads() {
        boolean result = false;
        ObjectMapper mapper = new ObjectMapper();
        try {
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.hasMorePayloadsCallbackUrl, mapper.writeValueAsString(""));
            result = mapper.readValue(responseStr, Boolean.class);
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }

        return result;
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        byte[] result = baseValue;
        ObjectMapper mapper = new ObjectMapper();

        try {
            String responseStr = this.httpClient.doPostJsonRequest(
                    this.getNextPayloadCallbackUrl, mapper.writeValueAsString(baseValue));
            List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>() {});
            MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);
            result = handler.applyActions(updates, null);
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }

        return result;
    }

    @Override
    public void reset() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            this.httpClient.doPostJsonRequest(this.resetCallbackUrl, mapper.writeValueAsString(""));
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }
}
