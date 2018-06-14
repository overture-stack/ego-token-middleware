import { get } from 'lodash';
import jwt from 'jsonwebtoken';

import { validateAccessRules, verifyJWT } from './utils';

export default function({ egoURL = process.env.EGO_API, accessRules = [] }) {
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
    try {
      valid = token && (await verifyJWT({ token, egoURL }));
    } catch (e) {
      valid = false;
    }

    const errorCode = validateAccessRules({
      url: req.originalUrl,
      user: get(valid, 'context.user', {}),
      valid,
      accessRules,
    });
    if (errorCode) {
      res.status(errorCode).json({ message: 'unauthorized' });
    } else {
      req.jwt = { ...jwt.decode(token), valid };
      next();
    }
  };
}
