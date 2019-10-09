'use strict';

const Hapi = require('@hapi/hapi');
const uuid4 = require('uuid/v4');
const { Issuer } = require('openid-client');
const scheme = require('./scheme');
const config = require('../env/config');

const init = async () => {
    const server = Hapi.server({
        port: config.Server.Port,
        host: config.Server.Name
    });

    // configure oidc provider & infra
    const issuer = await Issuer.discover(config.OpenIdConfiguration.DiscoveryUrl);
    console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);

    const client = new issuer.Client({
        client_id: config.OpenIdConfiguration.ClientId,
        redirect_uri: config.OpenIdConfiguration.CallbackUrl,
        response_types: config.OpenIdConfiguration.ResponseTypes,
    });

    // configure hapi authentication scheme
    server.auth.scheme('oidc', scheme({
        cookieName: config.OpenIdConfiguration.StateCookieName,
        callbackUrl: config.OpenIdConfiguration.CallbackUrl,
        scopes: config.OpenIdConfiguration.Scopes,
        client
    }));

    // configure hapi auth strategy
    server.auth.strategy('oidc', 'oidc', {
        password: uuid4(),
    });

    // sets oidc strategy as default
    server.auth.default("oidc");

    // unprotected splash page endpoint
    server.route([{
        method: 'GET',
        path: '/',
        handler: (request, h) => {
            if (request.auth.isAuthenticated) { // this should always be true
                return h.redirect("/me");
            }
            return "Hello! Let's get <a href='/signin'>signed in</a>.";
        },
        options: {
            auth: false
        }
    },
    // protected endpoint, noted by absence of 'options:auth' object
    {
        method: 'GET',
        path: '/me',
        handler: (request, h) => {
            if (request.auth.isAuthenticated) { // this should always be true
                var rows = Object.keys(request.auth.artifacts).map((x, i) => {
                    return "<tr key=" + i + "><td>" + x + "</td><td>" + request.auth.artifacts[x] + "</td></tr>";
                });
                return "<h2>hello</h2><table>" + rows + "</table>";
            }
            return h.redirect("/");
        }
    },
    // unprotected endpoint for login, note 'options:auth:false'
    {
        method: "GET",
        path: "/signin",
        handler: (request, h) => {
            return "<div>sign in! <a href='/me'>go</a></div>";
        },
        options: {
            auth: false
        }
    },
    // callback from oidc provider. parses cookie data for state/nonce to ensure they match
    // leaves token validation to openid-client, sets auth data in hapi pipeline and redirects home
    {
        method: 'POST',
        path: "/signin",
        handler: async (request, h) => {
            try {
                const state = request.state.oidc.state;
                const nonce = request.state.oidc.nonce;
                h.request.raw.req.body = request.payload; // input object to callbackParams needs to match http.incomingMessage signature
                const params = client.callbackParams(h.request.raw.req);
                const tokenSet = await client.callback(config.OpenIdConfiguration.CallbackUrl, params, { state, nonce });
                console.log('received and validated tokens %j', tokenSet);
                console.log('validated ID Token claims %j', tokenSet.claims());
                h.state(config.OpenIdConfiguration.StateCookieName, { credentials: tokenSet, artifacts: tokenSet.claims() });
                return h.redirect("/me");
            } catch (err) {
                request.log(['error', 'auth'], err.error_description);
                throw err;
            }
        },
        options: {
            auth: false
        }

    },
    // unprotected endpoint for signout, note 'options:auth:false'
    {
        method: "GET",
        path: "/signout",
        handler: (request, h) => {
            return h.redirect("/").unstate(config.OpenIdConfiguration.StateCookieName);
        },
        options: {
            auth: false
        }
    }
    ]);

    await server.start();
    console.log('Server running on %s', server.info.uri);
};

process.on('unhandledRejection', (err) => {
    console.log(err);
    process.exit(1);
});
init();