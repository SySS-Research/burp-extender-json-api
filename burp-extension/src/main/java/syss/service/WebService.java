package syss.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import syss.model.AnalyzedRequestResponse;
import syss.service.annotations.Secured;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.*;

/**
 * @author Torsten Lutz
 */
@Path("/")
@Secured
public class WebService {

    public static BurpService burpService;

    static Logger log = LogManager.getLogger();

    private String getErrorResult() {
        String result = "";
        try {
            ObjectMapper mapper = new ObjectMapper();
            result = mapper.writeValueAsString(Collections.singletonMap("status", "error"));
        } catch (Exception e) {
        }

        return result;
    }

    private String getOkResult() {
        String result = "";
        try {
            ObjectMapper mapper = new ObjectMapper();
            result = mapper.writeValueAsString(Collections.singletonMap("status", "ok"));
        } catch (Exception e) {
        }

        return result;
    }

// for debugging purposes
//    @GET
//    @Path("test")
//    @Produces(MediaType.TEXT_PLAIN)
//    public String test() {
//        return "Test";
//    }
//
//    @POST
//    @Path("posttest")
//    @Consumes(MediaType.APPLICATION_JSON)
//    @Produces(MediaType.APPLICATION_JSON)
//    public String postTest() {
//
//        log.info("test");
//        return "{}";
//    }

    @POST
    @Path("/register/scannerinsertionpointprovider")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerInsertionPointProvider(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            if (burpService.register(BurpService.ExtensionTypes.SCANNERINSERTIONPOINTPROVIDER, callbackUrl, name)) {
                result = mapper.writeValueAsString(Collections.singletonMap("status", "ok"));
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

//    @POST
//    @Path("/register/insertionpointprovider_simple")
//    @Consumes(MediaType.APPLICATION_JSON)
//    @Produces(MediaType.APPLICATION_JSON)
//    public String addInsertionPointSimple(String json) {
//        return "";
//    }

    @POST
    @Path("/register/intruderpayloadprocessor")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerIntruderPayloadProcessor(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            if (burpService.register(BurpService.ExtensionTypes.INTRUDERPAYLOADPROCESSOR, callbackUrl, name)) {
                result = this.getOkResult();
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/register/intruderpayloadgenerator")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerIntruderPayloadGenerator(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            result = mapper.writeValueAsString(Collections.singletonMap("status", "error"));
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            if (burpService.register(BurpService.ExtensionTypes.INTRUDERPAYLOADGENERATOR, callbackUrl, name)) {
                result = this.getOkResult();
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/register/messageeditortab")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerMessageEditorTab(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            result = mapper.writeValueAsString(Collections.singletonMap("status", "error"));
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            boolean alreadyRegistered = burpService.hasExtension(name);
            if (burpService.register(BurpService.ExtensionTypes.MESSAGEEDITORTAB, callbackUrl, name)) {
                HashMap<String, Object> resultMap = new HashMap<>();
                resultMap.put("status", "ok");
                resultMap.put("alreadyRegistered", alreadyRegistered);
                result = mapper.writeValueAsString(resultMap);
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/register/httplistener")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerHttpListener(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            result = mapper.writeValueAsString(Collections.singletonMap("status", "error"));
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            boolean alreadyRegistered = burpService.hasExtension(name);
            if (burpService.register(BurpService.ExtensionTypes.HTTPLISTENER, callbackUrl, name)) {
                HashMap<String, Object> resultMap = new HashMap<>();
                resultMap.put("status", "ok");
                resultMap.put("alreadyRegistered", alreadyRegistered);
                result = mapper.writeValueAsString(resultMap);
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/register/proxylistener")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerProxyListener(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            result = mapper.writeValueAsString(Collections.singletonMap("status", "error"));
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            boolean alreadyRegistered = burpService.hasExtension(name);
            if (burpService.register(BurpService.ExtensionTypes.PROXYLISTENER, callbackUrl, name)) {
                HashMap<String, Object> resultMap = new HashMap<>();
                resultMap.put("status", "ok");
                resultMap.put("alreadyRegistered", alreadyRegistered);
                result = mapper.writeValueAsString(resultMap);
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/register/sessionhandlingaction")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerSessionHandlingAction(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            result = mapper.writeValueAsString(Collections.singletonMap("status", "error"));
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            boolean alreadyRegistered = burpService.hasExtension(name);
            if (burpService.register(BurpService.ExtensionTypes.SESSIONHANDLINGACTION, callbackUrl, name)) {
                HashMap<String, Object> resultMap = new HashMap<>();
                resultMap.put("status", "ok");
                resultMap.put("alreadyRegistered", alreadyRegistered);
                result = mapper.writeValueAsString(resultMap);
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/register/scannercheck")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String registerScannerCheck(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            result = mapper.writeValueAsString(Collections.singletonMap("status", "error"));
            HashMap<String, String> data = mapper.readValue(json,
                    new TypeReference<Map<String, String>>() {
                    });
            String name = data.get("name");
            String callbackUrl = data.get("callbackUrl");

            boolean alreadyRegistered = burpService.hasExtension(name);
            if (burpService.register(BurpService.ExtensionTypes.SCANNERCHECK, callbackUrl, name)) {
                HashMap<String, Object> resultMap = new HashMap<>();
                resultMap.put("status", "ok");
                resultMap.put("alreadyRegistered", alreadyRegistered);
                result = mapper.writeValueAsString(resultMap);
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/getproxyhistory")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String getProxyHistory(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();
        List<AnalyzedRequestResponse> analyzedResult = new ArrayList<>();

        try {
            // create empty result
            result = mapper.writeValueAsString(analyzedResult);

            HashMap<String, Integer> data = mapper.readValue(json,
                    new TypeReference<Map<String, Integer>>() {
            });

            result = mapper.writeValueAsString(burpService.getProxyHistory(data.get("start"), data.get("stop")));

        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }

    @POST
    @Path("/resetall")
    @Produces(MediaType.APPLICATION_JSON)
    public String resetAll() {
        log.info("Triggered un-registering of all extensions");
        try {
            burpService.unRegisterAll();
        } catch (Exception e) {
            log.error(e);
        }
        return this.getOkResult();
    }

    @POST
    @Path("/reset")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public String reset(String json) {
        String result = this.getErrorResult();
        ObjectMapper mapper = new ObjectMapper();

        try {
            String name = mapper.readValue(json, String.class);
            if (burpService.unRegister(name)) {
                result = this.getOkResult();
            }
        } catch (Exception e) {
            log.error(e);
        }

        return result;
    }
}