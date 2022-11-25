import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction, RequestHandler } from 'express';

import { getKey } from './utils/verifyJWT';
import { UserJwtData, ApplicationJwtData, UserType } from 'jwtDataTypes';
import type { Identity } from 'jwtDataTypes';

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
      const parsedJwtData: UserJwtData | ApplicationJwtData = getValidatedJwtData(verifiedToken);

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

        const foo: Identity = {
          userId: parsedJwtData.sub,
          tokenInfo: parsedJwtData,
        };
        // inject identity in request object to make it accessible downstream.
        // const foo: Identity = {
        //   userId: parsedJwtData.sub,
        //   tokenInfo: {
        //     context: parsedJwtData.context,
        //     scope: parsedJwtData.context.scope
        //   },
        // };
        // const identity = getInfoFromToken(verifiedToken);
        // (req as any).identity = identity;
        (req as any).identity = foo;

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

function getInfoFromToken(decodedToken: UserJwtData): Identity {
  return {
    userId: decodedToken.sub,
    tokenInfo: decodedToken,
  };
}

function getValidatedJwtData(decodedToken: Object | string): UserJwtData | ApplicationJwtData {
  const mockUserToken: UserJwtData = {
    // userId: '1234',
    // tokenInfo: {
    sub: '1234',
    iat: 123,
    exp: 456,
    iss: 'ego',
    jti: 'jti123',
    aud: [],
    context: {
      scope: [''],
      user: {
        email: 'a',
        status: 'APPROVED',
        firstName: 'Ann',
        lastName: 'Catton',
        createdAt: 1580931064975,
        lastLogin: 1669299843399,
        preferredLanguage: '',
        providerType: 'GOOGLE',
        providerSubjectId: '',
        type: 'ADMIN' as UserType,
        groups: [],
      },
    },
    // },
  };

  const mockAppToken: ApplicationJwtData = {
    sub: '',
    nbf: 1669223158,
    scope: [''],
    iss: 'ego',
    context: {
      scope: [''],
      application: {
        name: '',
        clientId: '',
        redirectUri: '',
        status: 'APPROVED',
        errorRedirectUri: '',
        type: 'CLIENT',
      },
    },
    exp: 1670087158,
    iat: 1669223158,
    jti: '1',
  };
  return mockAppToken;
  // try {
  //   const userToken: UserJwtData = UserJwtData.parse(decodedToken)
  //   return userToken
  // } catch(err) {
  //   console.error('Failed to parse token as user jwt data.')
  //   try {
  //     const appToken: ApplicationJwtData = ApplicationJwtData.parse(decodedToken)
  //     return appToken
  //   } catch (err) {
  //     console.error('Failed to parse token as app jwt data')
  //     throw new Error('error')
  //   }
  // }
  // if (typeof decodedToken === 'string') {
  //   console.error('Unexpected token structure.');
  //   throw new UnauthorizedError('You need to be authenticated for this request.');
  // }
  // try {
  //   if (decodedToken.hasOwnProperty('context.user')) {
  //     const userToken = UserJwtData.parse(decodedToken);
  //     return userToken;
  //   } else if (decodedToken.hasOwnProperty('context.application')) {
  //     const appToken = ApplicationJwtData.parse(decodedToken);
  //     return appToken;
  //   } else {
  //     throw new Error('Unexpected token structure.');
  //   }
  //   // this will throw if parsing fails, but you still want to be able to try for an appToken
  // } catch (err) {
  //   console.error(err);
  //   throw new UnauthorizedError('You need to be authenticated for this request.');
  // }
}
