package syss;

import burp.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import syss.burpextension.SySSBurpObject;
import syss.model.MessageUpate;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * @author Torsten Lutz
 */
public class MessageUpdateHandler extends SySSBurpObject {

    static Logger log = LogManager.getLogger();
    private int[] lastParamOffsets;

    public MessageUpdateHandler(IBurpExtenderCallbacks burpCallbacks) {
        super(burpCallbacks);
    }

    public MessageUpdateHandler(IBurpExtenderCallbacks burpCallbacks, boolean logEnabled) {
        super(burpCallbacks);
        this.logEnabled = logEnabled;
    }

    public HashMap<byte[], int[]> applyActionSingle(MessageUpate update, byte[] requestResponse) {
        HashMap<byte[], int[]> result = new HashMap<>();

        List<MessageUpate> messageUpdates = new ArrayList<>();
        messageUpdates.add(update);
        result.put(this.applyActions(messageUpdates, requestResponse), this.lastParamOffsets);

        return result;
    }

    public byte[] applyActions(List<MessageUpate> messageUpdates, byte[] requestResponse) {
        byte[] result = requestResponse;
        this.lastParamOffsets = null;
        try {
            for (MessageUpate update : messageUpdates) {
                if (this.logEnabled) {
                    log.info("Handling update action " + update.getAction());
                }
                switch (update.getAction()) {
                    case UPDATE_PARAMETER:
                        IParameter oldParam = this.burpHelpers.getRequestParameter(result, update.getParamName());
                        if (null != oldParam) {
                            IParameter newParam = this.burpHelpers.buildParameter(
                                    update.getParamName(), update.getParamValue(), oldParam.getType());
                            result = this.burpHelpers.updateParameter(result, newParam);
                            IParameter updatedParam = this.burpHelpers.getRequestParameter(result, update.getParamName());
                            this.lastParamOffsets = new int[]{updatedParam.getValueStart(), updatedParam.getValueEnd()};
                        } else {
                            this.stderr.println("Parameter " + update.getParamName() + " not found");
                        }
                        break;
                    case ADD_PARAMETER:
                        result = this.burpHelpers.addParameter(result, this.burpHelpers.buildParameter(
                                update.getParamName(), update.getParamValue(), update.getParamType()));
                        IParameter addedParam = this.burpHelpers.getRequestParameter(result, update.getParamName());
                        this.lastParamOffsets = new int[]{addedParam.getValueStart(), addedParam.getValueEnd()};
                        break;
                    case DEL_PARAMETER:
                        IParameter delParam = this.burpHelpers.getRequestParameter(result, update.getParamName());
                        if (null != delParam) {
                            result = this.burpHelpers.removeParameter(result, delParam);
                        } else {
                            this.stderr.println("Parameter " + update.getParamName() + " not found");
                        }
                    case BUILD_HTTP_MESSAGE:
                        // WARNING: this will overwrite the whole message, previous changes will be ignored!
                        result = this.burpHelpers.buildHttpMessage(update.getHeaders(), update.getBody());
                        break;
                    case UPDATE_REQUEST_HEADERS:
                        IRequestInfo updateInfo = this.burpHelpers.analyzeRequest(result);
                        result = this.burpHelpers.buildHttpMessage(update.getHeaders(),
                                Arrays.copyOfRange(result, updateInfo.getBodyOffset(), result.length));
                        break;
                    case REPLACE_REQUEST_BODY:
                        IRequestInfo replReqInfo = this.burpHelpers.analyzeRequest(result);
                        ByteArrayOutputStream newReqBody = new ByteArrayOutputStream();
                        newReqBody.write(Arrays.copyOfRange(result, 0, replReqInfo.getBodyOffset()));
                        newReqBody.write(update.getBody());
                        result = this.burpHelpers.buildHttpMessage(replReqInfo.getHeaders(), newReqBody.toByteArray());
                    case REPLACE_RESPONSE_BODY:
                        IResponseInfo replRespInfo = this.burpHelpers.analyzeResponse(result);
                        ByteArrayOutputStream newRespBody = new ByteArrayOutputStream();
                        newRespBody.write(Arrays.copyOfRange(result, 0, replRespInfo.getBodyOffset()));
                        newRespBody.write(update.getBody());
                        result = this.burpHelpers.buildHttpMessage(update.getHeaders(), newRespBody.toByteArray());
                        break;
                    case REPLACE_REQUEST_RESPONSE:
                    case SET_PAYLOAD:
                        result = update.getBody();
                        break;
                    case BASE64_DECODE_BODY:
                        result = this.burpHelpers.base64Decode(update.getBody());
                        break;
                    default:
                        this.stderr.println("Unknown update action: " + update.getAction());
                }
            }
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }

        return result;
    }

    public void applyActions(
            boolean messageIsRequest, List<MessageUpate> messageUpdates, IInterceptedProxyMessage message) {
        List<MessageUpate> unhandledUpdates = new ArrayList<>();

        for (MessageUpate update : messageUpdates) {
            if (this.logEnabled) {
                log.info("Handling update action " + update.getAction());
            }

            switch (update.getAction()) {
                case ACTION_DO_INTERCEPT:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DO_INTERCEPT);
                    break;
                case ACTION_DO_INTERCEPT_AND_REHOOK:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DO_INTERCEPT_AND_REHOOK);
                    break;
                case ACTION_DONT_INTERCEPT:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
                    break;
                case ACTION_DONT_INTERCEPT_AND_REHOOK:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT_AND_REHOOK);
                    break;
                case ACTION_DROP:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                    break;
                case ACTION_FOLLOW_RULES:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES);
                    break;
                case ACTION_FOLLOW_RULES_AND_REHOOK:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK);
                    break;
                default:
                    unhandledUpdates.add(update);
            }
        }

        if (messageIsRequest) {
            message.getMessageInfo().setRequest(
                    this.applyActions(unhandledUpdates, message.getMessageInfo().getRequest()));
        } else {
            message.getMessageInfo().setResponse(
                    this.applyActions(unhandledUpdates, message.getMessageInfo().getResponse()));
        }
    }

}