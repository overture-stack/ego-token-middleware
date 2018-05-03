import jwt from 'jsonwebtoken';
import verifyJWT from './verifyJWT';
import { get } from 'lodash';

export default function({
  required,
  egoURL = process.env.EGO_API,
  requireUserApproval = process.env.REQUIRE_USER_APPROVAL,
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
      requireUserApproval &&
      !get(valid, 'context.user.roles', []).includes('ADMIN') &&
      get(valid, 'context.user.status') !== 'Approved'
    ) {
      res.status(403).json({ message: 'forbidden' });
    } else {
      req.jwt = { ...jwt.decode(token), valid };
      next();
    }
  };
}
