// modified from https://github.com/JbIPS/hapi-oidc

const Hoek = require('@hapi/hoek');
const { generators } = require('openid-client');
const nonce = generators.nonce();
const COOKIE_DEFAULTS = {
    ttl: 3600 * 1000,
    isSecure: false, // todo: fix this
    isHttpOnly: true,
    encoding: 'base64json',
    clearInvalid: true,
    strictHeader: true,
    isSameSite: false,
    domain: "localhost", // todo: fix this to come off request url
    path: "/"
};

module.exports = ({
    cookieName, callbackUrl, scope, client,
}) => (server, schemeOptions) => {
    const schemeConfig = Hoek.applyToDefaults(COOKIE_DEFAULTS, schemeOptions);
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
                scope,
                state,
                nonce
            });

            return h.redirect(redirectUrl).takeover();
        },
    };
};