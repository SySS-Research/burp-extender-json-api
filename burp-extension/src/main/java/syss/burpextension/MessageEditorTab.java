package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.ITextEditor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import syss.MessageUpdateHandler;
import syss.model.HttpService;
import syss.model.AnalyzedMessage;
import syss.model.MessageUpate;

import java.awt.Component;
import java.util.Arrays;
import java.util.List;

/**
 * @author Torsten Lutz
 */
public class MessageEditorTab extends SySSBurpObject implements IMessageEditorTab {

    private String setMessageCallbackUrl;
    private String getMessageCallbackUrl;
    private String tabCaption;
    private ITextEditor txtInput;
    private boolean cacheEnabled;
    private boolean isRequest = false;
    private boolean editable;
    private byte[] currentMessage;

    public MessageEditorTab(IBurpExtenderCallbacks burpCallbacks, String tabCaption, String getMessageCallbackUrl,
                            String setMessageCallbackUrl, boolean cacheEnabled,
                            IMessageEditorController controller, boolean editable) {
        super(burpCallbacks);
        this.tabCaption = tabCaption;
        this.getMessageCallbackUrl = getMessageCallbackUrl;
        this.setMessageCallbackUrl = setMessageCallbackUrl;
        this.editable = editable;
        this.cacheEnabled = cacheEnabled;
        this.txtInput = this.burpCallbacks.createTextEditor();
        this.txtInput.setEditable(this.editable);
    }

    @Override
    public String getTabCaption() {
        return this.tabCaption;
    }

    @Override
    public Component getUiComponent() {
        return this.txtInput.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        try {
            if (null == content) {
                this.txtInput.setText(null);

            } else if (!(this.cacheEnabled && Arrays.equals(this.currentMessage, content))) {
                ObjectMapper mapper = new ObjectMapper();
                AnalyzedMessage setMsgRequest = new AnalyzedMessage();
                this.isRequest = isRequest;
                if (isRequest) {
                    // provide dummy, mapping will throw exception otherwise
                    HttpService dummy = new HttpService();
                    setMsgRequest.setAnalyzedRequest(this.burpHelpers.analyzeRequest(dummy, content));
                    setMsgRequest.setRequest(content);
                } else {
                    setMsgRequest.setAnalyzedResponse(this.burpHelpers.analyzeResponse(content));
                    setMsgRequest.setResponse(content);
                }

                String responseStr = this.httpClient.doPostJsonRequest(
                        this.setMessageCallbackUrl, mapper.writeValueAsString(setMsgRequest), this.logEnabled);

                List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>(){});
                MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);
                this.txtInput.setText(handler.applyActions(updates, content));

            }
            this.currentMessage = content;

        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    @Override
    public byte[] getMessage() {
        byte[] result = this.currentMessage;
        try {
            if (this.isModified()) {
                ObjectMapper mapper = new ObjectMapper();
                AnalyzedMessage getMsgRequest = new AnalyzedMessage();

                if (this.isRequest) {
                    // provide dummy, mapping will throw exception otherwise
                    HttpService dummy = new HttpService();
                    getMsgRequest.setAnalyzedRequest(this.burpHelpers.analyzeRequest(dummy, this.txtInput.getText()));
                    getMsgRequest.setRequest(this.txtInput.getText());
                } else {
                    getMsgRequest.setAnalyzedResponse(this.burpHelpers.analyzeResponse(this.txtInput.getText()));
                    getMsgRequest.setResponse(this.txtInput.getText());
                }

                String responseStr = this.httpClient.doPostJsonRequest(
                        this.getMessageCallbackUrl, mapper.writeValueAsString(getMsgRequest), this.logEnabled);

                List<MessageUpate> updates = mapper.readValue(responseStr, new TypeReference<List<MessageUpate>>() {});
                MessageUpdateHandler handler = new MessageUpdateHandler(this.burpCallbacks, this.logEnabled);

                result = handler.applyActions(updates, result);
            }
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }

        return result;
    }

    @Override
    public boolean isModified() {
        return this.txtInput.isTextModified();
    }

    @Override
    public byte[] getSelectedData() {
        return this.txtInput.getSelectedText();
    }
}
