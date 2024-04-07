const express = require('express');
const fs = require("fs");
const jose = require('node-jose');
const bodyParser = require('body-parser');

const app = express();
const port = process.env.PORT || 3000;

const JWKS_FILE = './jwks.json';

function initializeServer() {
    const keyStore = jose.JWK.createKeyStore();
    keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig'}).then(() => {
        fs.writeFileSync(
            JWKS_FILE,
            JSON.stringify(keyStore.toJSON(true), null, '  ')
        )
    });
}

initializeServer();

// Middleware to parse JSON bodies
app.use(bodyParser.json());

app.get('/.well-known/jwks.json', (req, res) => {
    const jwks = JSON.parse(fs.readFileSync(JWKS_FILE, 'utf8'));
    res.send(jwks);
});

app.post('/oauth/token', async (req, res) => {
    const jwks = fs.readFileSync(JWKS_FILE, 'utf8')
    const keyStore = await jose.JWK.asKeyStore(jwks.toString())
    const [key] = keyStore.all({use: 'sig'})

    const opt = {compact: true, jwk: key, fields: {typ: 'jwt'}}

    const payload = {
        exp: Math.floor((Date.now() + 1000000) / 1000),
        iat: Math.floor(Date.now() / 1000),
        sub: 'test',
    };

    for (const prop in req.body) {
        payload[prop] = req.body[prop];
    }

    const access_token = await jose.JWS.createSign(opt, key)
    .update(JSON.stringify(payload))
    .final();

    res.send({access_token})
});

app.listen(port, () => {
    console.log(`Server is listening at http://localhost:${port}`);
});