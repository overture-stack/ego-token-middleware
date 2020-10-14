import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction, RequestHandler } from 'express';
import { getKey } from './utils/verifyJWT';

export default function(keyUrl?: string, key?: string) {
  if (!keyUrl && !key) {
    throw new Error('must provide either key url or key to validate tokens');
  }
  return handler(keyUrl, key);
}

const handler = (keyUrl?: string, key?: string) =>
  (authorizedScopes: string[]): RequestHandler => {
    return async (req: Request, res: Response, next: NextFunction) => {
      const { authorization: authorizationHeader } = req.headers;
      const { authorization: authorizationBody }: any = req.body || {};
      const authorization = authorizationHeader || authorizationBody;
      const token: string | undefined =  authorization?.split(' ')[1];
      let publicKey = undefined;

      try {
        publicKey = key ? key : await getKey(keyUrl as string);
        if (publicKey == undefined) {
          throw new Error('invalid key');
        }
      } catch (err) {
        // failed to get the key (ego could be down)
        next(new Error('failed to fetch token key:' + err));
        return;
      }
      let valid = false;
      let decodedToken: { [key: string]: any } | undefined = undefined;
      // no token, or empty token provided
      if (token == undefined || token == '') {
        valid = false;
        next(new UnauthorizedError('You need to be authenticated for this request.'));
        return;
      }

      // decode the token, if invalid throw unauthorized error
      try {
          decodedToken = jwt.verify(token, publicKey) as { [key: string]: any } ;
      } catch (e) {
        console.error('failed to verify token.', e);
        next(new UnauthorizedError('You need to be authenticated for this request.'));
        return;
      }

      // check if any of the required scopes are there
      try {
        const scopes = decodedToken['context']['scope'] as Array<string>;
        if (!scopes.some(s => authorizedScopes.includes(s))) {
          next(new ForbiddenError('Forbidden'));
          return;
        }
        next();
        return;
      } catch (e) {
        console.error('failed to verify scopes', e);
        next(new ForbiddenError('Forbidden'));
        return;
      }
    };
  };
export class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Unauthorized';
  }
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Forbidden';
  }
}
