package mil.nga.keycloak.social;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.keycloak.models.*;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import mil.nga.keycloak.keys.loader.LoginGovPublicKeyStorageManager;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.security.PublicKey;

public class LoginGovIdentityProvider
        extends OIDCIdentityProvider
        implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    public static final String CAC_SUBJECT_ATTR = "subjectDN";
    public static final String CAC_UUID_ATTR = "cacUID";

    public static final String IS_DOD_CAC_TEXT = "OU=DoD";
    public static final String IS_FED_CAC_TEXT = "O=U.S. Government";

    public static final String EMAIL_SCOPE = "email";
    public static final String OPENID_SCOPE = "openid";
    public static final String X509_SCOPE = "x509:subject";
    public static final String DEFAULT_SCOPE = OPENID_SCOPE + " "
            + X509_SCOPE + " "
            + EMAIL_SCOPE;
    private KeycloakSession session = null;

    private static final Logger log = Logger.getLogger(LoginGovIdentityProvider.class);

    public LoginGovIdentityProvider(KeycloakSession session, LoginGovIdentityProviderConfig config) {
        super(session, config);
        this.session = session;
        String defaultScope = config.getDefaultScope();

        if (defaultScope == null || defaultScope.trim().isEmpty()) {
            config.setDefaultScope(DEFAULT_SCOPE);
        } else {
            config.setDefaultScope(defaultScope + " " + DEFAULT_SCOPE);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);

        LoginGovIdentityProviderConfig config = (LoginGovIdentityProviderConfig) getConfig();
        uriBuilder.queryParam("acr_values", new Object[] { config.getAcrValues() });
        logger.debugv("Login.gov Authorization Url: {0}", uriBuilder.toString());
        return uriBuilder;
    }

    /**
     * Verify the token is signed by the IDP with the JWK exposed by the wellknown
     * endpoints.
     * Overriden from parent because of an issue with login.gov / Keycloak
     * interpretation of the JWK Spec 4.2.
     * https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.2
     *
     * Login.gov does NOT set the "use" field, which should be set to "sig".
     * Keycloak does not default the
     * "use" field and therefore will not validate with JWK endpoint provided by
     * login.gov.
     *
     * This implementation defaults the JWK by setting the null "use" fields to
     * "sig"
     * allowing validation with login.gov.
     *
     * @param jws - signed token
     * @return true if validation is successful, false otherwise
     */
    @Override
    protected boolean verify(JWSInput jws) {
        if (!getConfig().isValidateSignature())
            return true;

        try {
            PublicKey publicKey = LoginGovPublicKeyStorageManager.getIdentityProviderPublicKey(session,
                    session.getContext().getRealm(), getConfig(), jws);

            return publicKey != null && RSAProvider.verify(jws, publicKey);
        } catch (Exception e) {
            logger.debug("Failed to verify token", e);
            return false;
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken,
            JsonWebToken idToken) throws IOException {
        BrokeredIdentityContext identityContext = super.extractIdentity(tokenResponse, accessToken, idToken);
        final String email = identityContext.getEmail();

        /**
         * Get some custom claims from login.gov so we can interact with the user from
         * here.
         */
        final String x509_subject = (String) idToken.getOtherClaims().get(LoginGovToken.X509_SUBJECT);
        logger.info("-- x509_subject --");
        logger.info(x509_subject);

        /**
         * Set custom attributes from Login.gov so that application are able to read
         * them.
         */
        if (x509_subject != null) {
            identityContext.setUserAttribute(CAC_SUBJECT_ATTR, x509_subject);
            identityContext.setUserAttribute(CAC_UUID_ATTR, extractUniqueIdentifierFromNormalizedDN(x509_subject));
            identityContext.setUsername(extractCNFromNormalizedDN(x509_subject));
        }

        if (email == null || email.isEmpty()) {
            throw new IdentityBrokerException("Unable to determine user email address.");
        }
        identityContext.setEmail(email.toLowerCase());

        return identityContext;
    }

    /**
     * Due to the complexity of the card (multiple OU enteries on each card for
     * example) we are using a very basic implementation currently. The
     * implementation
     * will be to simple string out the series of number on the SubjectDN and assume
     * that is the unique identifier.
     *
     * On a PIV:
     * Subject: C=US, O=U.S. Government, OU=Department of the Interior,
     * OU=Geological Survey/UID=00000000000000, CN=FIRST_NAME LAST_NAME (Affiliate)
     *
     * On a CAC:
     * Subject: C=US, O=U.S. Government, OU=DoD, OU=PKI, OU=CONTRACTOR,
     * CN=LAST_NAME.FIRST_NAME.MIDDLE_NAME.0000000000
     *
     */
    private String extractUniqueIdentifierFromNormalizedDN(String normDN) {
        Pattern pattern = Pattern.compile(".*?(\\d+).*");
        Matcher matcher = pattern.matcher(normDN);
        while (matcher.find()) {
            String UID = matcher.group(1);
            return UID;
        }
        return "";
    }

    private String extractCNFromNormalizedDN(String normDN) {
        Pattern pattern = Pattern.compile(".*CN=?(.+[0-9])(?:,|$)");
        Matcher matcher = pattern.matcher(normDN);
        while (matcher.find()) {
            String CN = matcher.group(1);
            return CN;
        }
        return "";
    }

}
