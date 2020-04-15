package syss.burpextension;

import burp.IBurpExtenderCallbacks;

/**
 * @author Torsten Lutz
 */
public abstract class SySSBurpExtension extends SySSBurpObject {


    public SySSBurpExtension(IBurpExtenderCallbacks burpCallbacks) {
        super(burpCallbacks);
    }

    public SySSBurpExtension(IBurpExtenderCallbacks burpCallbacks, String callbackUrl) {
        super(burpCallbacks, callbackUrl);
    }

    public abstract void register();

    public abstract void unRegister();

}
