package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderPayloadProcessor;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.MessageUpdateHandler;
import syss.model.MessageUpate;
import syss.model.ProcessPayloadRequest;

import java.util.List;

/**
 * @author Torsten Lutz
 */
public class IntruderPayloadProcessor extends SySSBurpExtension implements IIntruderPayloadProcessor {

    private String name;

    public IntruderPayloadProcessor(IBurpExtenderCallbacks burpCallbacks, String callbackUrl, String processorName) {
        super(burpCallbacks, callbackUrl);
        this.name = processorName;
    }

    public String getProcessorName() {
        return this.name;
    }

    public void register() {
        this.burpCallbacks.registerIntruderPayloadProcessor(this);
    }

    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        byte[] result = currentPayload;
        ObjectMapper mapper = new ObjectMapper();

        try {
            ProcessPayloadRequest ppr = new ProcessPayloadRequest();
            ppr.setCurrentPayload(currentPayload);
            ppr.setOriginalPayload(originalPayload);
            ppr.setBaseValue(baseValue);

            String responseStr = this.httpClient.doPostJsonRequest(this.callbackUrl, mapper.writeValueAsString(ppr));
            List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>() {});
            MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);
            result = handler.applyActions(updates, null);
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }

        return result;
    }

    public void unRegister() {
        this.burpCallbacks.removeIntruderPayloadProcessor(this);
    }
}
