package totp.keycloak.resource;

import com.google.common.hash.Hashing;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
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
}
