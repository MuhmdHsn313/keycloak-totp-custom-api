package totp.keycloak.resource;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Map;

import static totp.keycloak.resource.Utils.checkUser;


/**
 * @author Shogun Nassar
 */
@JBossLog
@RequiredArgsConstructor
//@Path("/realms/{realm}/" + MyResourceProviderFactory.PROVIDER_ID)
public class MyResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @APIResponse(
            responseCode = "200",
            description = "",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )


    @POST
    @Path("createTotp")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createTotp(Map<String, String> data) {
        UserModel userModel = checkUser(session).getUser();
        RealmModel realm = session.getContext().getRealm();
        long count = userModel.credentialManager().getStoredCredentialsByTypeStream("otp").count();
        if (count > 0) {
            throw new WebApplicationException(Response.Status.CONFLICT);
        }
        String secret = data.get("secret");
        OTPCredentialModel otp = OTPCredentialModel.createTOTP(secret, 6, 30, "HmacSHA1");
        otp.setUserLabel("TOTP");
        new OTPCredentialProvider(session).createCredential(realm, userModel, otp);
        return Response.ok(true).build();
    }

    @DELETE
    @Path("deleteTotp")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteTotp(@FormParam("code") String code) {
        UserModel userModel = checkUser(session).getUser();
        RealmModel realm = session.getContext().getRealm();
        CredentialModel credentialModel = userModel.credentialManager().getStoredCredentialsByTypeStream("otp").findAny().orElseThrow(() -> new WebApplicationException(Response.Status.BAD_REQUEST));
        boolean isValid = CredentialValidation.validOTP(code, OTPCredentialModel.createFromCredentialModel(credentialModel), 0);
        if (isValid) {
            new OTPCredentialProvider(session).deleteCredential(realm, userModel, credentialModel.getId());
        } else {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }

        return Response.ok(true).build();
    }


}
