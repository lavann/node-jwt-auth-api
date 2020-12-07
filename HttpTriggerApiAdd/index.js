const express = require('express');
const passport = require('passport');
const auth = require('../auth.json');
const https = require('https'); //allow the ability to make https calls
const querystring = require('querystring');
const { json } = require('body-parser');
const { Http2ServerResponse } = require('http2');
const { kMaxLength } = require('buffer');

const createHandler = require('azure-function-express').createHandler;

const BearerStrategy = require("passport-azure-ad").BearerStrategy;

const options = {
    identityMetadata: `https://${auth.authority}/${auth.tenantID}/${auth.version}/${auth.discovery}`,
    issuer: `https://${auth.authority}/${auth.tenantID}/${auth.version}`,
    clientID: auth.clientID,
    audience: auth.audience,
    validateIssuer: auth.validateIssuer,
    passReqToCallback: auth.passReqToCallback,
    loggingLevel: auth.loggingLevel,
    scope: auth.scope
};

console.log(options)

const bearerStrategy = new BearerStrategy(options, (token, done) => {
    // Send user info using the second argument
    done(null, {}, token);
});

const app = express();

app.use(require('morgan')('combined'));

app.use(require('body-parser').urlencoded({ 'extended': true }));

app.use(passport.initialize());

passport.use(bearerStrategy);

// Enable CORS (for local testing only -remove in production/deployment)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Authorization, Origin, X-Requested-With, Content-Type, Accept');
    next();
});

// Expose and protect API endpoint
app.get('/api/getData', passport.authenticate('oauth-bearer', { session: false }),
    (req, res) => {

        //Does the incoming contain hasGroups ??
        //If they do, they are a member of more than 5 security groups and so an internall call will need to be made to the GraphAPI
        if (req.authInfo["hasgroups"]) {
            console.log('has more than 5 groups');

            //need to use a client id and secret to obtain the bearer token to the graph API
            //the app registration needs an applicaiton permission User.Read.All - need to grant admin consent once added
            //this is required so the api can call the graph endpoint to retrieve the security groups for the user
            //the user id is obtained through the incoming bearer token          
            var _hostname = `${auth.authority}`;
            var _path = `/${auth.tenantID}/oauth2/v2.0/token`;

            var post_data = querystring.stringify({
                'grant_type': 'client_credentials',
                'client_id': auth.clientID, // client ID from app registration need to store as variables
                'client_secret': auth.clientSecret, //client secret - see document on how to create secret need to store as variales
                'scope': 'https://graph.microsoft.com/.default'
            });

            var _postOptions = {
                hostname: _hostname,
                port: 443,
                path: _path,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(post_data)
                }
            }

            var graphReg = https.request(_postOptions, (resp) => {
                let data = '';
                // This may need to be modified based on your server's response.
                resp.setEncoding('utf8');
                // A chunk of data has been recieved.
                resp.on('data', (chunk) => {
                    data += chunk;
                });
                // The whole response has been received. Print out the result.
                resp.on('end', () => {
                    var graphRequestResuslt = JSON.parse(data); // we have the token at this point and are now able to call the graph api
                    // [access_token]

                    var httpGetGraphRequestOptions = {
                        hostname: 'graph.microsoft.com',
                        port: 443,
                        path: `/v1.0/users/${req.authInfo['oid']}/memberOf`,
                        method: 'GET',
                        headers: {
                            Authorization: `Bearer ${graphRequestResuslt['access_token']}`
                        }
                    }

                    https.get(httpGetGraphRequestOptions, (resp) => {
                        let data = '';
                        // A chunk of data has been recieved.
                        resp.on('data', (chunk) => {
                            data += chunk;
                        });
                        // The whole response has been received. Print out the result.
                        resp.on('end', () => {
                            //1res.status(200).send(JSON.parse(data)['value']);
                            //ctrl + k then c comment
                            //ctrl + k then u uncomments


                            let tempSecurityGroups = [];
                            tempSecurityGroups = JSON.parse(data)['value'];
                            let adminGroup = tempSecurityGroups.find(i => i.id = auth.reportAdminGroup); // this needs to be a variable - object id of the report admin ad group 
                            /*
                             {
                                "@odata.type": "#microsoft.graph.group",
                                "id": "'ebde25e7-d254-474e-ae33-cd491aa98ebf",
                                "deletedDateTime": null,
                                "classification": null,
                                "createdDateTime": null,
                                "creationOptions": [],
                                "description": null,
                                "displayName": null,
                                "expirationDateTime": null,
                                "groupTypes": [],
                                "isAssignableToRole": null,
                                "mail": null,
                                "mailEnabled": null,
                                "mailNickname": null,
                                "membershipRule": null,
                                "membershipRuleProcessingState": null,
                                "onPremisesDomainName": null,
                                "onPremisesLastSyncDateTime": null,
                                "onPremisesNetBiosName": null,
                                "onPremisesSamAccountName": null,
                                "onPremisesSecurityIdentifier": null,
                                "onPremisesSyncEnabled": null,
                                "preferredDataLocation": null,
                                "preferredLanguage": null,
                                "proxyAddresses": [],
                                "renewedDateTime": null,
                                "resourceBehaviorOptions": [],
                                "resourceProvisioningOptions": [],
                                "securityEnabled": null,
                                "securityIdentifier": null,
                                "theme": null,
                                "visibility": null,
                                "onPremisesProvisioningErrors": []
                            }
                            the returned payload has an extra quote "id": "'ebde25e7-d254-474e-ae33-cd491aa98ebf",
                            need to remove the quote
                            */

                            //we don't want to return the whole object - as the response from AAD if a user is in less than 5 groups is to return an array of groups
                            //we will do the same so that we are returning a consisent message
                            let securityGroup = [];

                            securityGroup.push(adminGroup['id']);
                            res.status(200).send(securityGroup);

                        });
                    }).on("error", (err) => {
                        // console.log("Error: " + err.message);
                        res.status(500).send(err.message);
                    });
                });
            }).on("error", (err) => {
                res.status(500).send(err)
            });
            graphReg.write(post_data);
            graphReg.end();


        } else {
            console.log('has less than 5 groups');
            res.status(200).send(req.authInfo['groups']);
        }


    }
);

module.exports = createHandler(app);