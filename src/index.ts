import { get } from 'lodash';
import jwt from 'jsonwebtoken';

import { validateAccessRules, verifyJWT } from './utils';
import { Request, Response } from 'express';
import { NextFunction } from 'connect';

export default function(egoURL: string = process.env.EGO_API, accessRules: Array<AccessRule> = []) {
  if (!egoURL) {
    throw new Error(
      'must provide ego url with either the `EGO_API` env variable or egoURL argument',
    );
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    const { authorization: authorizationHeader } = req.headers;
    const { authorization: authorizationBody }: any = req.body || {};

    const authorization = authorizationHeader || authorizationBody;
    const token = authorization ? authorization.split(' ')[1] : req.query.key;

    let valid = false;
    try {
      valid = !!(token && (await verifyJWT(token, egoURL)));
    } catch (e) {
      valid = false;
    }

    const error = validateAccessRules(req.originalUrl, get(valid, 'context.user', {}), accessRules, valid);
    if (error) {
      res.status(error.code).json({ message: error.message });
    } else {
      req.jwt = { 
        ...(jwt.decode(token) as ({[key: string]: any})), valid
      };
      next();
    }
  };
}
