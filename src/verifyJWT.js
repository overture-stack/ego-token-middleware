import memoize from "memoizee";
import axios from "axios";
import ms from "ms";
import jwt from "jsonwebtoken";
import urlJoin from "url-join";

const getKey = memoize(
  async egoURL => {
    const response = await axios.get(urlJoin(egoURL, "oauth/token/public_key"));
    return response.data;
  },
  {
    maxAge: ms("3h"),
    preFetch: true
  }
);

export default async function({ token, egoURL }) {
  const key = await getKey(egoURL);
  return jwt.verify(token, key);
}
