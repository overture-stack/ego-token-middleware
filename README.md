# ego-token-middleware

Express middleware for validating ego JWT

## Usage

```
import egoToken from 'ego-token-middleware';
const app = express();
app.use(egoToken({ required: true }));
```

The Ego JWT must be included in in the request as `authorization` in either
the body or the header, with the format `"Bearer __TOKEN__"` where `__TOKEN__`
is the token.

This middleware needs the request to be ran through `body-parser` by the consuming app.

## Options

* `required` - if true, send 401 error on invalid token. default: `false`
* `egoURL` - url of ego to fetch public key from. default: the value of `process.env.EGO_API`
