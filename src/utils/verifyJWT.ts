import memoize from 'memoizee';
import axios from 'axios';
import ms from 'ms';
import jwt from 'jsonwebtoken';

export const getKey = memoize(
  async (keyUrl: string) => {
    const response = await axios.get(keyUrl, {
      timeout: 10 * 1000,
    });
    return response.data;
  },
  {
    maxAge: ms(process.env.KEY_REFRESH_INTERVAL_EXPRESSION || '1h'),
    preFetch: true,
  },
);

export default async function (token: string, key: string) {
  return jwt.verify(token, key);
}
