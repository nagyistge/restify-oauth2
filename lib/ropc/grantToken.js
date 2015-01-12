"use strict";

var validateGrantTokenRequest = require("../common/validateGrantTokenRequest");
var finishGrantingToken = require("../common/finishGrantingToken");
var makeOAuthError = require("../common/makeOAuthError");

module.exports = function grantToken(req, res, next, options) {
    function sendUnauthorizedError(type, description) {
        if (!options.allowAnonymousClient && options.sendWWWAuthenticate) res.header("WWW-Authenticate", "Basic realm=\"" + description + "\"");
        next(makeOAuthError("Unauthorized", type, description));
    }


    if (!validateGrantTokenRequest("password", req, next, options)) {
        return;
    }

    var username = req.body.username;
    var password = req.body.password;

    if (!username) {
        return next(makeOAuthError("BadRequest", "invalid_request", "Must specify username field."));
    }

    if (!password) {
        return next(makeOAuthError("BadRequest", "invalid_request", "Must specify password field."));
    }

    var process = function(clientId, clientSecret) {
        var allCredentials = { clientId: clientId, clientSecret: clientSecret, username: username, password: password };
        options.hooks.grantUserToken(allCredentials, req, function (error, token) {
            if (error) {
                return next(error);
            }

            if (!token) {
                return sendUnauthorizedError("invalid_grant", "Username and password did not authenticate.");
            }

            var allCredentials = {
                clientId: clientId,
                clientSecret: clientSecret,
                username: username,
                password: password,
                token: token
            };
            finishGrantingToken(allCredentials, token, options, req, res, next);
        });
    };

    if (!options.allowAnonymousClient) {
        var clientId = req.authorization.basic.username;
        var clientSecret = req.authorization.basic.password;
        var clientCredentials = { clientId: clientId, clientSecret: clientSecret };

        options.hooks.validateClient(clientCredentials, req, function (error, result) {
            if (error) {
                return next(error);
            }

            if (!result) {
                return sendUnauthorizedError("invalid_client", "Client ID and secret did not validate.");
            }

            process(clientId, clientSecret);
        });
    }
    else {
        process(null, null);
    }

};
