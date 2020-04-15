package syss.model;

import java.util.List;

public class SessionHandlingActionRequest {

    private AnalyzedMessage currentRequest;
    private List<AnalyzedMessage> macroItems;

    public AnalyzedMessage getCurrentRequest() {
        return currentRequest;
    }

    public void setCurrentRequest(AnalyzedMessage currentRequest) {
        this.currentRequest = currentRequest;
    }

    public List<AnalyzedMessage> getMacroItems() {
        return macroItems;
    }

    public void setMacroItems(List<AnalyzedMessage> macroItems) {
        this.macroItems = macroItems;
    }
}
