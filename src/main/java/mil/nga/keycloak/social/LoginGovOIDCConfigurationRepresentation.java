package mil.nga.keycloak.social;

import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class LoginGovOIDCConfigurationRepresentation extends OIDCConfigurationRepresentation {

    @JsonProperty("deepLogout")
    private Boolean deepLogout;

    public Boolean getDeepLogout() {
        return deepLogout;
    }

    public void setDeepLogout(Boolean deepLogout) {
        this.deepLogout = deepLogout;
    }

}
