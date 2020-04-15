package syss.model;

import burp.IParameter;

/**
 * @author Torsten Lutz
 */
public class Parameter implements IParameter {

    private String name;
    private String value;
    private int nameStart;
    private int nameEnd;
    private int valueStart;
    private int valueEnd;

    public Parameter(String name, String value, int nameStart, int nameEnd, int valueStart, int valueEnd) {
        this.name = name;
        this.value = value;
        this.nameStart = nameStart;
        this.nameEnd = nameEnd;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
    }

    @Override
    public byte getType() {
        return IParameter.PARAM_BODY;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getValue() {
        return this.value;
    }

    @Override
    public int getNameStart() {
        return this.nameStart;
    }

    @Override
    public int getNameEnd() {
        return this.nameEnd;
    }

    @Override
    public int getValueStart() {
        return this.valueStart;
    }

    @Override
    public int getValueEnd() {
        return this.valueEnd;
    }
}
