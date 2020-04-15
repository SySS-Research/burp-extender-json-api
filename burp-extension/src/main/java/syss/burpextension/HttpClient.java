package syss.burpextension;

import burp.IBurpExtenderCallbacks;
import org.apache.http.NoHttpResponseException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.ws.rs.core.HttpHeaders;
import java.nio.charset.StandardCharsets;

/**
 * @author Torsten Lutz
 */
public class HttpClient {

    static Logger log = LogManager.getLogger();
    private String logName = "";
    private IBurpExtenderCallbacks burpCallbacks;
    private CloseableHttpClient httpClient;
    RequestConfig config;

    public HttpClient(IBurpExtenderCallbacks callbacks) {
        this.init(callbacks);
    }

    public HttpClient(IBurpExtenderCallbacks callbacks, String logName) {
        this.logName = logName;
        this.init(callbacks);
    }

    private void init(IBurpExtenderCallbacks callbacks) {
        this.burpCallbacks = callbacks;
        //this.httpClient = HttpClientBuilder.create().build();
        this.httpClient = HttpClients.createDefault();
        // TODO: request timeout does not seem to work
        this.config = RequestConfig.custom()
                .setConnectTimeout(1000)
                .setConnectionRequestTimeout(2000)
                .setSocketTimeout(2000)
                .build();
    }

    public String doPostJsonRequest(String url, String json) {
        return this.doPostJsonRequest(url, json, false);
    }

    public String doPostJsonRequest(String url, String json, boolean logEnabled) {
        String result = "";

        HttpPost request = new HttpPost(url);
        request.setConfig(this.config);
        request.setHeader(HttpHeaders.AUTHORIZATION, this.burpCallbacks.loadExtensionSetting("token"));
        try {
            request.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
            if (logEnabled) {
                log.info("Triggering request (" + this.logName + ")");
            }
            CloseableHttpResponse response = this.httpClient.execute(request);
            if (logEnabled) {
                log.info("Request done (" + this.logName + ")");
            }
            result = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            if (logEnabled) {
                log.debug(result);
            }
            response.close();
        } catch (NoHttpResponseException e) {
            log.error("Got no response calling " + url + "(" + this.logName + ")");
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }
}
