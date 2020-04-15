package burp;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.WriterAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.core.config.Configurator;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import syss.service.AuthFilter;
import syss.service.BurpService;
import syss.service.WebService;

import javax.ws.rs.core.UriBuilder;
import java.io.PrintWriter;
import java.io.Writer;


public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    private final static int LOCAL_PORT = 8099;
    static Logger log = LogManager.getLogger();
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private HttpServer grizzlyServer;
    private BurpService burpService;


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // obtain our output stream
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // avoid log4j properties file since we would have to determine the path
        // -> configure logging here
        Configurator.setRootLevel(Level.DEBUG);
        this.addAppender(this.stdout, "burp out");
        log.info("Logging set up");

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // set our extension name
        callbacks.setExtensionName("SySS Burp JSON API");

        // register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(this);

        this.burpService = new BurpService(this);
        // ugly
        WebService.burpService = this.burpService;
        AuthFilter.burpService = this.burpService;

        // register WebService class
        ResourceConfig rc = new ResourceConfig();
        rc.registerClasses(WebService.class, AuthFilter.class);

        this.grizzlyServer = GrizzlyHttpServerFactory.createHttpServer(
                UriBuilder.fromUri("http://localhost/").port(LOCAL_PORT).build(),
                rc
        );
        try {
            this.grizzlyServer.start();
        } catch (Exception e) {
            e.printStackTrace(this.stderr);
        }
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    private void addAppender(final Writer writer, final String writerName) {
        final LoggerContext context = LoggerContext.getContext(false);
        final Configuration config = context.getConfiguration();
        final PatternLayout layout = PatternLayout.createDefaultLayout(config);
        final Appender appender = WriterAppender.createAppender(layout, null, writer, writerName, false, true);
        appender.start();
        config.addAppender(appender);
        updateLoggers(appender, config);
    }

    private void updateLoggers(final Appender appender, final Configuration config) {
        final Level level = null;
        final Filter filter = null;
        for (final LoggerConfig loggerConfig : config.getLoggers().values()) {
            loggerConfig.addAppender(appender, level, filter);
        }
        config.getRootLogger().addAppender(appender, level, filter);
    }

    public void extensionUnloaded() {
        try {
            this.grizzlyServer.shutdownNow();
            this.burpService.unRegisterAll();
        } catch (Exception e) {
            log.error(e);
        }
        log.info("Extension was unloaded");
    }
}