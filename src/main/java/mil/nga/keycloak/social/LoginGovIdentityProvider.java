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

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.security.PublicKey;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;

public class LoginGovIdentityProvider
        extends OIDCIdentityProvider
        implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    public static final String CAC_SUBJECT_ATTR = "subjectDN";
    public static final String CAC_UUID_ATTR = "cacUID";
    public static final String X509_PRESENTED_ATTR = "x509_presented";

    public static final String IS_DOD_CAC_TEXT = "OU=DoD";
    public static final String IS_FED_CAC_TEXT = "O=U.S. Government";

    public static final String EMAIL_SCOPE = "email";
    public static final String OPENID_SCOPE = "openid";
    public static final String X509_SCOPE = "x509:subject";
    public static final String X509_PRESENTED_SCOPE = "x509_presented";
    public static final String DEFAULT_SCOPE = OPENID_SCOPE + " "
            + X509_SCOPE + " "
            + X509_PRESENTED_SCOPE  + " "
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

        // final String x509_presented = (String) idToken.getOtherClaims().get(LoginGovToken.X509_PRESENTED);
        // logger.info("-- x509_presented --");
        // logger.info(x509_presented);

        /**
         * Set custom attributes from Login.gov so that application are able to read
         * them.
         */
        if (x509_subject != null) {
            logger.info("-- x509_presented --");
            identityContext.setUserAttribute(X509_PRESENTED_ATTR, "true");
            identityContext.setUserAttribute(CAC_SUBJECT_ATTR, x509_subject);
            identityContext.setUserAttribute(CAC_UUID_ATTR, extractUniqueIdentifierFromNormalizedDN(x509_subject));
            identityContext.setUsername(extractCNFromNormalizedDN(x509_subject));
        } else {
            logger.info("-- no x509_presented --");
            identityContext.setUserAttribute(X509_PRESENTED_ATTR, "false");
        }

        if (email == null || email.isEmpty()) {
            throw new IdentityBrokerException("Unable to determine user email address.");
        }
        identityContext.setEmail(email.toLowerCase());

        return identityContext;
    }

    /**
     * To avoid deleting users as the only way to capture new/changed values, certain values will be updated on login.
     * credit: https://stackoverflow.com/questions/57912634/update-keycloak-user-data-based-on-data-present-in-identity-provider-token/58002033#58002033
     */
    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, 
        UserModel user, BrokeredIdentityContext context) {
        user.setSingleAttribute(X509_PRESENTED_ATTR,context.getUserAttribute(X509_PRESENTED_ATTR));
    }

    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        LoginGovIdentityProviderConfig config = (LoginGovIdentityProviderConfig)getConfig();

        if(config.getDeepLogoutValue()) {
            /**
             * Due to login.gov no longer accepting id_token_hint (@see: https://developers.login.gov/oidc/#logout) we need
             * to override the KeyCloak method to ensure that client_id is sent instead of the id_token_hint.
             *
             * To be clear the recommended approach is to use id_token_hint per the spec:
             *  https://openid.net/specs/openid-connect-rpinitiated-1_0.html
             *
             * For default / original implementation./
             * @see https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/broker/oidc/OIDCIdentityProvider.java#L165-L185
             */
            if (getConfig().getLogoutUrl() == null || getConfig().getLogoutUrl().trim().equals("")) return null;
            String clientId = getConfig().getClientId();
            String sessionId = userSession.getId();

            UriBuilder logoutUri = UriBuilder.fromUri(getConfig().getLogoutUrl())
                    .queryParam("state", sessionId);
            if (clientId != null) logoutUri.queryParam("client_id", clientId);

            String redirect = RealmsResource.brokerUrl(uriInfo)
                    .path(IdentityBrokerService.class, "getEndpoint")
                    .path(OIDCEndpoint.class, "logoutResponse")
                    .build(realm.getName(), getConfig().getAlias()).toString();
            logoutUri.queryParam("post_logout_redirect_uri", redirect);

            Response response = Response.status(302).location(logoutUri.build()).build();
            return response;

        } else {
            /*
             * Setting dictate that the user should not be logged out of login.gov.
             * Returning null here means that there is no additional logout redirect.
             */
            return null;
        }
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
