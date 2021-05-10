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
      let decodedToken: EgoJwtData | undefined = undefined;
      // no token, or empty token provided
      if (!token) {
        valid = false;
        next(new UnauthorizedError('You need to be authenticated for this request.'));
        return;
      }

      // decode the token, if invalid throw unauthorized error
      try {
        decodedToken = jwt.verify(token, publicKey) as EgoJwtData;
      } catch (e) {
        console.error('failed to verify token.', e);
        next(new UnauthorizedError('You need to be authenticated for this request.'));
        return;
      }

      // check if any of the required scopes are there
      try {
        const scopes = decodedToken.context.scope;
        if (authorizedScopes
          && authorizedScopes.length > 0
          && !scopes.some(s => authorizedScopes.includes(s))) {

          next(new ForbiddenError('Forbidden'));
          return;
        }

        // inject identity in request object to make it accessible downstream.
        const identity = getInfoFromToken(decodedToken);
        (req as any).identity = identity;

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

function getInfoFromToken(decodedToken: EgoJwtData): Identity {
  return {
    userId: decodedToken.sub,
    tokenInfo: decodedToken,
  };
}

export type Identity = {
  userId: string;
  tokenInfo: EgoJwtData,
};

export declare enum UserStatus {
  APPROVED = 'APPROVED',
  DISABLED = 'DISABLED',
  PENDING = 'PENDING',
  REJECTED = 'REJECTED'
}

export declare enum UserType {
  ADMIN = 'ADMIN',
  USER = 'USER'
}

export declare type EgoJwtData = {
  iat: number;
  exp: number;
  sub: string;
  iss: string;
  aud: string[];
  jti: string;
  context: {
      scope: string[];
      user: {
          name: string;
          email: string;
          status: UserStatus;
          firstName: string;
          lastName: string;
          createdAt: number;
          lastLogin: number;
          preferredLanguage: string | undefined;
          type: UserType;
      };
  };
};