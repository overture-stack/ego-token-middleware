import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction, RequestHandler } from 'express';

import { getKey } from './utils/verifyJWT';
import { UserJwtData, ApplicationJwtData } from 'jwtDataTypes';

export default function (keyUrl?: string, key?: string) {
  if (!keyUrl && !key) {
    throw new Error('must provide either key url or key to validate tokens');
  }
  return handler(keyUrl, key);
}

const handler = (keyUrl?: string, key?: string) => (authorizedScopes: string[]): RequestHandler => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { authorization: authorizationHeader } = req.headers;
    const { authorization: authorizationBody }: any = req.body || {};
    const authorization = authorizationHeader || authorizationBody;
    const token: string | undefined = authorization?.split(' ')[1];
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

    // no token, or empty token provided
    if (!token) {
      next(new UnauthorizedError('You need to be authenticated for this request.'));
      return;
    }

    // decode the token, if invalid throw unauthorized error
    try {
      // verify the token with the public key
      const verifiedToken = jwt.verify(token, publicKey);
      // try parsing the token as user or app jwt data
      const parsedJwtData = getValidatedJwtData(verifiedToken);

      // check if any of the required scopes are there
      try {
        const scopes = parsedJwtData.context.scope;
        if (
          authorizedScopes &&
          authorizedScopes.length > 0 &&
          !scopes.some((s) => authorizedScopes.includes(s))
        ) {
          next(new ForbiddenError('Forbidden'));
          return;
        }

        const identityFromJwt = {
          userId: parsedJwtData.sub,
          tokenInfo: parsedJwtData,
        };
        // inject identity in request object to make it accessible downstream.
        (req as any).identity = identityFromJwt;

        next();
        return;
      } catch (e) {
        console.error('failed to verify scopes', e);
        next(new ForbiddenError('Forbidden'));
        return;
      }
    } catch (e) {
      console.error('failed to verify token.', e);
      next(new UnauthorizedError('You need to be authenticated for this request.'));
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

function getValidatedJwtData(decodedToken: Object | string): UserJwtData | ApplicationJwtData {
  try {
    const userToken = UserJwtData.parse(decodedToken);
    return userToken;
  } catch (userTokenErr) {
    console.error('err as user token: ', userTokenErr);
    try {
      const appToken = ApplicationJwtData.parse(decodedToken);
      return appToken;
    } catch (appTokenErr) {
      console.error('Err as app token: ', appTokenErr);
      throw new UnauthorizedError('Unexpected token structure.');
    }
  }
}
