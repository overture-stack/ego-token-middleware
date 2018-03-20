# ego-token-middleware
## Usage
```
import egoToken from 'ego-token-middleware';
const app = express();
app.use(egoToken({ required: true }));
```

## Options
required - if true, send 401 error on invalid token. default: `false`
egoURL - url of ego to fetch public key from. default: the value of `process.env.EGO_API`