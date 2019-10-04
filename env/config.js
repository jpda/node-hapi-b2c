module.exports = {
    OpenIdConfiguration: {
        CallbackUrl: process.env.OPENIDCONFIGURATION_CALLBACK_URL || "http://localhost:3000/signin",
        ClientId: process.env.OPENIDCONFIGURATION_CLIENT_ID || "<client_id>",
        ResponseTypes: process.env.OPENIDCONFIGURATION_RESPONSE_TYPES || ["id_token"],
        Scopes: process.env.OPENIDCONFIGURATION_SCOPES || "openid profile",
        DiscoveryUrl: process.env.OPENIDCONFIGURATION_DISCOVERY_URL || "https://<your b2c tenant>.b2clogin.com/<your b2c tenant>.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=<b2c policy name>",
        StateCookieName: process.env.OPENIDCONFIGURATION_STATE_COOKIE_NAME || "oidc"
    },
    Server: {
        Port: process.env.SERVER_PORT || 3000,
        Name: process.env.SERVER_NAME || "localhost"
    }
}