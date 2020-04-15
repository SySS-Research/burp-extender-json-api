package syss.model;

/**
 * @author Torsten Lutz
 */
public class ProcessPayloadRequest {

    byte[] currentPayload;
    byte[] originalPayload;
    byte[] baseValue;

    public byte[] getCurrentPayload() {
        return this.currentPayload;
    }

    public void setCurrentPayload(byte[] currentPayload) {
        this.currentPayload = currentPayload;
    }

    public byte[] getOriginalPayload() {
        return this.originalPayload;
    }

    public void setOriginalPayload(byte[] originalPayload) {
        this.originalPayload = originalPayload;
    }

    public byte[] getBaseValue() {
        return this.baseValue;
    }

    public void setBaseValue(byte[] baseValue) {
        this.baseValue = baseValue;
    }
}
