package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.PrintWriter;

/**
 * @author Torsten Lutz
 */
public class SySSBurpObject {

    static Logger log = LogManager.getLogger();
    protected PrintWriter stderr;
    protected PrintWriter stdout;
    protected IBurpExtenderCallbacks burpCallbacks;
    protected HttpClient httpClient;
    protected boolean logEnabled = true;
    protected String callbackUrl;
    protected IExtensionHelpers burpHelpers;

    public SySSBurpObject(IBurpExtenderCallbacks burpCallbacks) {
        this.init(burpCallbacks, null);
    }

    public SySSBurpObject(IBurpExtenderCallbacks burpCallbacks, String callbackUrl) {
        this.init(burpCallbacks, callbackUrl);
    }

    protected void init(IBurpExtenderCallbacks burpCallbacks, String callbackUrl) {
        this.burpCallbacks = burpCallbacks;
        this.burpHelpers = this.burpCallbacks.getHelpers();
        this.callbackUrl = callbackUrl;
        this.httpClient = new HttpClient(this.burpCallbacks, this.getClass().getName());
        this.stdout = new PrintWriter(burpCallbacks.getStdout(), true);
        this.stderr = new PrintWriter(burpCallbacks.getStderr(), true);
    }

    public void setLogging(boolean status) {
        this.logEnabled = status;
    }

    public String getCallbackUrl() {
        return this.callbackUrl;
    }
}
