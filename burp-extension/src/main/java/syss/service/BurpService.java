package syss.service;



import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import syss.burpextension.HttpListener;
import syss.burpextension.ProxyListener;
import syss.burpextension.*;
import syss.model.AnalyzedRequestResponse;

import java.io.PrintWriter;
import java.util.*;

/**
 * @author Torsten Lutz
 */
public class BurpService {

    static Logger log = LogManager.getLogger();

    public enum ExtensionTypes {
        INTRUDERPAYLOADPROCESSOR,
        INTRUDERPAYLOADGENERATOR,
        SCANNERINSERTIONPOINTPROVIDER,
        MESSAGEEDITORTAB,
        HTTPLISTENER,
        PROXYLISTENER,
        SESSIONHANDLINGACTION,
        SCANNERCHECK,
    }

    public PrintWriter stdout;
    public PrintWriter stderr;
    private BurpExtender extender;
    private HashMap<String, SySSBurpExtension> registeredExtensions;


    public BurpService(BurpExtender extender) {
        //PropertyConfigurator.configure("log4j.properties");
        this.extender = extender;
        this.registeredExtensions = new HashMap<>();
        this.stdout = new PrintWriter(this.getCallbacks().getStdout(), true);
        this.stderr = new PrintWriter(this.getCallbacks().getStderr(), true);
        String token = this.getCallbacks().loadExtensionSetting("token");
        if (null == token) {
            token = UUID.randomUUID().toString();
            this.getCallbacks().saveExtensionSetting("token", token);
        }
        this.stdout.println("Authorization token: " + token);
    }

    public String getAuthorizationToken() {
        return this.getCallbacks().loadExtensionSetting("token");
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.extender.getCallbacks();
    }

    public boolean register(ExtensionTypes type, String callbackUrl, String name) {
        boolean result = false;
        SySSBurpExtension extension = null;
        //log.info("Trying to register " + type + ", callback: " + callbackUrl + ", name: " + name);
        log.info("Trying to register " + type + ", callback: " + callbackUrl + ", name: " + name);

        switch (type) {
            case INTRUDERPAYLOADPROCESSOR:
                extension = new IntruderPayloadProcessor(this.getCallbacks(), callbackUrl, name);
                break;
            case INTRUDERPAYLOADGENERATOR:
                extension = new IntruderPayloadGeneratorFactory(this.getCallbacks(), callbackUrl, name);
                break;
            case SCANNERINSERTIONPOINTPROVIDER:
                extension = new ScannerInsertionPointProvider(this.getCallbacks(), callbackUrl);
                break;
            case MESSAGEEDITORTAB:
                extension = new MessageEditorTabFactory(this.getCallbacks(), callbackUrl);
                break;
            case HTTPLISTENER:
                extension = new HttpListener(this.getCallbacks(), callbackUrl);
                break;
            case PROXYLISTENER:
                extension = new ProxyListener(this.getCallbacks(), callbackUrl);
                break;
            case SESSIONHANDLINGACTION:
                extension = new SessionHandlingAction(this.getCallbacks(), callbackUrl, name);
                break;
            case SCANNERCHECK:
                extension = new ScannerCheck(this.getCallbacks(), callbackUrl);
                break;
            default:
                this.stderr.println("Unknown extension " + type);
                log.warn("Unknown extension " + type);
                break;
        }
        if (null != extension) {
            if (this.unRegister(name)) {
                //log.info("Extension was already registered: " + name + ". Re-registering...");
                log.info("Extension was already registered: " + name + ". Re-registering...");
            }
            extension.register();
            this.registeredExtensions.put(name, extension);
            //log.info("Registered extension '" + name + "'");
            log.info("Registered extension '" + name + "'");
            result = true;
        }

        return result;
    }

    public boolean unRegister(String name) {
        boolean result = false;

        if (this.hasExtension(name)) {
            this.registeredExtensions.get(name).unRegister();
            this.registeredExtensions.remove(name);
            log.info("Removed extension '" + name + "'");
            result = true;
        }

        return result;
    }

    public boolean hasExtension(String name) {
        return null != this.registeredExtensions.get(name);
    }

    public void unRegisterAll() {
        for (String key : this.registeredExtensions.keySet()) {
            this.unRegister(key);
        }
    }

    public List<AnalyzedRequestResponse> getProxyHistory(int start, int stop) {
        // create empty result
        List<AnalyzedRequestResponse> analyzedResult = new ArrayList<>();
        IHttpRequestResponse[] proxyHistory = this.getCallbacks().getProxyHistory();

        if (stop < 0) {
            // get rest of the history
            stop = proxyHistory.length;
        }
        // get only one
        else if (stop <= start) {
            stop = start;
        }
        // trim length to maximum
        stop = Math.min(stop, proxyHistory.length);

        // burp starts counting at 1 instead of 0 in displayed history
        // -> decrease by 1
        start -= 1;
        if (start < 1) {
            start = 1;
        }

        log.info("Getting history from " + start + " until " + stop);

        // slice array and iterate
        for (IHttpRequestResponse requestResponse: Arrays.copyOfRange(proxyHistory, start, stop)) {
            AnalyzedRequestResponse analyzedReqResp = new AnalyzedRequestResponse();
            // set request data
            analyzedReqResp.setRequest(requestResponse.getRequest());
            analyzedReqResp.setAnalyzedRequest(
                    this.getCallbacks().getHelpers().analyzeRequest(requestResponse));

            // responses can be empty, i.e. if an error occurred
            if (null != requestResponse.getResponse()) {
                // set response data
                analyzedReqResp.setResponse(requestResponse.getResponse());
                analyzedReqResp.setAnalyzedResponse(
                        this.getCallbacks().getHelpers().analyzeResponse(requestResponse.getResponse()));
            }
            // add to list
            analyzedResult.add(analyzedReqResp);
        }

        return analyzedResult;
    }
}
