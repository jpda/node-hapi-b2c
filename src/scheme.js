// modified from https://github.com/JbIPS/hapi-oidc
const Url = require('url');
const { applyToDefaults } = require('@hapi/hoek');
const { generators } = require('openid-client');

const nonce = generators.nonce();
const COOKIE_DEFAULTS = {
    ttl: 3600 * 1000,
    isHttpOnly: true,
    encoding: 'base64json',
    clearInvalid: true,
    strictHeader: true,
    isSameSite: false,
    path: "/"
};

module.exports = ({ cookieName, callbackUrl, scopes, client, }) =>
    (server, schemeOptions) => {
        var url = Url.parse(callbackUrl);
        COOKIE_DEFAULTS.isSecure = url.protocol.toUpperCase() === "HTTPS:";
        COOKIE_DEFAULTS.domain = url.hostname;

        const schemeConfig = applyToDefaults(COOKIE_DEFAULTS, schemeOptions);
        server.state(cookieName, schemeConfig);
        return {
            authenticate: async (request, h) => {
                const oidc = request.state[cookieName];
                if (oidc && oidc.credentials) {
                    const { credentials, artifacts } = oidc;
                    return h.authenticated({ credentials, artifacts });
                }
                const state = request.route.path;
                h.state(cookieName, { state, nonce });
                const redirectUrl = client.authorizationUrl({
                    redirect_uri: callbackUrl,
                    response_mode: 'form_post',
                    scopes,
                    state,
                    nonce
                });

                return h.redirect(redirectUrl).takeover();
            },
        };
    };