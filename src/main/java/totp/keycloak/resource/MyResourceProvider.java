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
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.CredentialHelper;

import java.util.HashMap;
import java.util.Map;

import static totp.keycloak.resource.Utils.checkUser;
import static totp.keycloak.resource.Utils.getUserModel;


/**
 * @author Shogun Nassar
 */
@JBossLog
@RequiredArgsConstructor
//@Path("/realms/{realm}/" + MyResourceProviderFactory.PROVIDER_ID)
public class MyResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(CredentialHelper.class);


    private final KeycloakSession session;

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @APIResponse(responseCode = "200", description = "", content = {@Content(schema = @Schema(implementation = Response.class, type = SchemaType.OBJECT))})


    @POST
    @Path("generateKey")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateKey(Map<String, String> data) {
        // Check if the request authenticated
        AuthenticationManager.AuthResult authResult = checkUser(session);

        // Get current user
        UserModel user = getUserModel(authResult, session, data.get("user_id"));

        // Get current realm
        RealmModel realm = authResult.getClient().getRealm();

        // Generate the secret
        String secret = HmacOTP.generateSecret(20);
        // Encode the secret for authenticator apps like Google Authenticator
        String secretEncoded = TotpUtils.encode(secret);

        // Create a map for response body
        Map<String, String> dt = new HashMap<>();
        dt.put("secret", secret);
        dt.put("secret_encoded", secretEncoded);
        dt.put("qr", TotpUtils.qrCode(secret, realm, user));
        return Response.ok(dt).build();
    }

    @POST
    @Path("createTotp")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createTotp(Map<String, String> data) {
        // Check if the request authenticated
        AuthenticationManager.AuthResult authResult = checkUser(session);

        // Get current user
        UserModel user = getUserModel(authResult, session, data.get("user_id"));

        // Get current realm
        RealmModel realm = authResult.getClient().getRealm();


        long count = user.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).count();
        if (count > 0) {
            throw new WebApplicationException(Response.Status.CONFLICT);
        }

        // Generate secret for TOTP
        String secret = data.get("secret");
        OTPCredentialModel credentialModel = OTPCredentialModel.createFromPolicy(realm, secret, "TOTP");

        CredentialProvider otpCredentialProvider = session.getProvider(CredentialProvider.class, "keycloak-otp");
        String totpSecret = credentialModel.getOTPSecretData().getValue();

        UserCredentialModel otpUserCredential = new UserCredentialModel("", realm.getOTPPolicy().getType(), totpSecret);
        boolean userStorageCreated = user.credentialManager().updateCredential(otpUserCredential);

        String credentialId = null;
        if (userStorageCreated) {
            logger.infof("Created OTP credential for user '%s' in the user storage", user.getUsername());
        } else {
            CredentialModel createdCredential = otpCredentialProvider.createCredential(realm, user, credentialModel);
            credentialId = createdCredential.getId();
        }

        String totpCode = data.get("totp");
        //If the type is HOTP, call verify once to consume the OTP used for registration and increase the counter.
        UserCredentialModel credential = new UserCredentialModel(credentialId, otpCredentialProvider.getType(), totpCode);
        boolean isValid = user.credentialManager().isValid(credential);

        if (!isValid) {
            throw new WebApplicationException("totp is not valid", Response.Status.BAD_REQUEST);
        }

        return Response.noContent().build();
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
