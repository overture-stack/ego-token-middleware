import jwt from 'jsonwebtoken';
import verifyJWT from './verifyJWT';

export default function({ required, egoURL = process.env.EGO_API }) {
  return async (req, res, next) => {
    const { authorization } = req.headers;
    const token = authorization ? authorization.split(' ')[1] : req.query.key;
    const valid = await verifyJWT({ token, egoURL });

    if (!valid && required) {
      res.status(401).send('unauthorized');
    } else {
      req.jwt = { ...jwt.decode(token), valid };
      next();
    }
  };
}
