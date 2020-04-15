package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

/**
 * @author Torsten Lutz
 */
public class IntruderPayloadGeneratorFactory extends SySSBurpExtension implements IIntruderPayloadGeneratorFactory {

    private String name;

    public IntruderPayloadGeneratorFactory(IBurpExtenderCallbacks burpCallbacks, String callbackUrl, String generatorName) {
        super(burpCallbacks, callbackUrl);
        this.name = generatorName;
    }

    public void register() {
        this.burpCallbacks.registerIntruderPayloadGeneratorFactory(this);
    }

    @Override
    public String getGeneratorName() {
        return this.name;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return new IntruderPayloadGenerator(this.burpCallbacks, this.callbackUrl, attack);
    }



    public void unRegister() {
        this.burpCallbacks.removeIntruderPayloadGeneratorFactory(this);
    }
}
