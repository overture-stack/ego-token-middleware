import { get } from 'lodash';
import jwt from 'jsonwebtoken';

import { validateAccessRules, verifyJWT } from './utils';

export default function({
  required,
  egoURL = process.env.EGO_API,
  accessRules = [],
}) {
  if (!egoURL) {
    throw new Error(
      'must provide ego url with either the `EGO_API` env variable or egoURL argument',
    );
  }

  return async (req, res, next) => {
    const { authorization: authorizationHeader } = req.headers;
    const { authorization: authorizationBody } = req.body || {};

    const authorization = authorizationHeader || authorizationBody;

    const token = authorization ? authorization.split(' ')[1] : req.query.key;

    let valid = false;
    let error;
    try {
      valid = token && (await verifyJWT({ token, egoURL }));
    } catch (e) {
      error = e;
      valid = false;
    }

    if (required && !valid) {
      res.status(401).json(error || { message: 'unauthorized' });
    } else if (
      !validateAccessRules({
        url: req.originalUrl,
        user: get(valid, 'context.user', {}),
        accessRules,
      })
    ) {
      res.status(403).json(error || { message: 'forbidden' });
    } else {
      req.jwt = { ...jwt.decode(token), valid };
      next();
    }
  };
}
