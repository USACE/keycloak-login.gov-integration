package mil.nga.keycloak.social;

import org.keycloak.representations.IDToken;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class LoginGovToken extends IDToken {
    // X509_SUBJECT
    public static final String X509_SUBJECT = "x509_subject";

    @JsonProperty(X509_SUBJECT)
    protected String x509_subject;

    public String getX509_Subject() {
        return this.x509_subject;
    }

    // X509_PRESENTED
    public static final String X509_PRESENTED = "x509_presented";

    @JsonProperty(X509_PRESENTED)
    protected String x509_presented;

    public void setX509_Presented(String X509_presented) {
        this.x509_presented = X509_presented;
    }

    public String getX509_Presented() {
        return this.x509_presented;
    }

}
