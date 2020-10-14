# ego-token-middleware

Express middleware for validating ego JWT

[![Slack](http://slack.overture.bio/badge.svg)](http://slack.overture.bio)

## Usage

```
import Auth from 'ego-token-middleware';
const app = express();
...
ِconst authFilter = Auth(jwtKeyUrl)(WRITE_SCOPE)
app.get('/protected', authFilter, (req: Request, res: Response) => {
  return res.send('I am protected');
});
```

The Ego JWT must be included in in the request as `authorization` in either
the body or the header, with the format `"Bearer __TOKEN__"` where `__TOKEN__`
is the token.

This middleware needs the request to be ran through `body-parser` by the consuming app.

## Options
