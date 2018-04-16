import jwt from "jsonwebtoken";
import verifyJWT from "./verifyJWT";

export default function({ required, egoURL = process.env.EGO_API }) {
  if (!egoURL) {
    throw new Error(
      "must provide ego url with either the `EGO_API` env variable or egoURL argument"
    );
  }

  return async (req, res, next) => {
    const { authorization: authorizationHeader } = req.headers;
    const { authorization: authorizationBody } = req.body;
    const authorization = authorizationHeader || authorizationBody;

    const token = authorization ? authorization.split(" ")[1] : req.query.key;
    const valid = token && (await verifyJWT({ token, egoURL }));

    if (!valid && required) {
      res.status(401).send("unauthorized");
    } else {
      req.jwt = { ...jwt.decode(token), valid };
      next();
    }
  };
}
