package totp.keycloak.resource;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * @author Shogun Nassar
 */
@AutoService(RealmResourceProviderFactory.class)
public class MyResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "totp-apis";

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new MyResourceProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
