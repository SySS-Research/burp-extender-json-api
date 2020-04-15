package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import syss.model.MessageEditorGetConfigResponse;

/**
 * @author Torsten Lutz
 */
public class MessageEditorTabFactory extends SySSBurpExtension implements IMessageEditorTabFactory {

    private String setMessageCallbackUrl;
    private String getMessageCallbackUrl;
    private String tabCaption;
    private boolean editable;
    private boolean cacheEnabled;

    public MessageEditorTabFactory(IBurpExtenderCallbacks burpCallbacks, String callbackUrl) {
        super(burpCallbacks, callbackUrl);
    }

    @Override
    public void register() {
        this.burpCallbacks.registerMessageEditorTabFactory(this);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        if (null == this.setMessageCallbackUrl) {
            ObjectMapper mapper = new ObjectMapper();

            try {
                String responseStr = this.httpClient.doPostJsonRequest(this.callbackUrl, mapper.writeValueAsString(""), this.logEnabled);

                MessageEditorGetConfigResponse mydata = mapper.readValue(responseStr, MessageEditorGetConfigResponse.class);
                this.tabCaption = mydata.getCaption();
                this.cacheEnabled = mydata.isCacheEnabled();
                this.editable = mydata.isEditable();
                this.getMessageCallbackUrl = mydata.getGetMessageCallbackUrl();
                this.setMessageCallbackUrl = mydata.getSetMessageCallbackUrl();
            } catch (Exception e) {
                e.printStackTrace(this.stderr);
            }
        }
        return new MessageEditorTab(this.burpCallbacks, this.tabCaption, this.getMessageCallbackUrl,
                this.setMessageCallbackUrl, this.cacheEnabled, controller, this.editable);
    }

    @Override
    public void unRegister() {
        this.burpCallbacks.removeMessageEditorTabFactory(this);
    }
}
