package totp.keycloak.resource;

import com.google.common.hash.Hashing;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class Utils {
    public static void checkAdmin(KeycloakSession session) {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        } else if (auth.getToken().getIssuedFor() == null || !auth.getToken().getIssuedFor().equals("admin-cli")) {
            throw new ForbiddenException("Token is not properly issued for admin-cli");
        }

    }

    public static AuthenticationManager.AuthResult checkUser(KeycloakSession session) {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        } else if (auth.getToken().getIssuedFor() == null) {
            throw new ForbiddenException("Token is not properly issued for admin-cli");
        }
        return auth;
    }

    public static void checkOTP(String otp, String userDBCode) {
        String userCodeHashed = Hashing.sha256().hashString(otp, StandardCharsets.UTF_8).toString();
        if (userDBCode == null || !Objects.equals(userDBCode, userCodeHashed)) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
    }

    public static boolean validatePassword(UserModel user, String password) {

        if (password == null || password.isEmpty()) {
            throw new ErrorResponseException("Error", "No Password provided",
                    Response.Status.BAD_REQUEST);
        }

        if (user.credentialManager().isValid(UserCredentialModel.password(password))) {
            return true;
        } else {
            throw new ErrorResponseException("Error", "Invalid Password",
                    Response.Status.BAD_REQUEST);
        }
    }

    private static final String REQUIRED_ROLE = "manage-authorization";
    private static final String REQUIRED_RESOURCE = "realm-management";

    public static UserModel getUserModel(AuthenticationManager.AuthResult authResult, KeycloakSession session, String userId) {
        // Check if the request comes from client or user
        boolean isClient = authResult.getToken().getOtherClaims().get("client_id") != null;

        // Create new point for the user that will OTP generate for him
        UserModel user = null;

        // Get an instance from current realm
        RealmModel realm = session.getContext().getRealm();

        // If client call this endpoint, user_id should be sent in body request, if not the user of the token will set.
        if (isClient) {
            // Check if the client access token has the right role
            AccessToken.Access realmManagement = authResult.getToken().getResourceAccess().get(REQUIRED_RESOURCE);
            if (realmManagement == null || !realmManagement.getRoles().contains(REQUIRED_ROLE)) {
                throw new WebApplicationException(Response.Status.FORBIDDEN);
            }

            if (userId == null || userId.isEmpty()) {
                throw new WebApplicationException("user_id is required",Response.Status.BAD_REQUEST);
            }
            user = session.users().getUserById(realm, userId);
        } else {
            user = authResult.getUser();
        }

        return user;
    }
}
