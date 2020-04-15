package syss.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import syss.service.annotations.Secured;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;


@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthFilter implements ContainerRequestFilter {

    private static Logger log = LogManager.getLogger();
    public static BurpService burpService;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null) {
            String token = authorizationHeader.trim();
            // this comparison is not timing safe, but ignored in this scenario
            if (token.equals(burpService.getAuthorizationToken())) {
                return;
            }
        }
        log.info("Request unauthorized");
        requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
    }
}
