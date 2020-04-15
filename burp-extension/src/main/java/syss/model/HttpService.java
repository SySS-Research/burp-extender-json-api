package syss.model;

import burp.IHttpService;

/**
 * @author Torsten Lutz
 */
public class HttpService implements IHttpService {

    private String host = "DUMMYHOST";
    private int port = 1337;
    private String protocol = "http";

    @Override
    public String getHost() {
        return this.host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    @Override
    public int getPort() {
        return this.port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    @Override
    public String getProtocol() {
        return this.protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
}
