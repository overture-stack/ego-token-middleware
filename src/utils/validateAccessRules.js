import { reverse } from 'lodash/fp';
import { keys } from 'lodash';
import pathToRegexp from 'path-to-regexp';

const UNAUTHORIZED = { code: 401, message: 'unauthorized' };
const FORBIDDEN = { code: 403, message: 'forbidden' };

const toLower = x => (x || '').toLowerCase();

const ensureArray = x => (Array.isArray(x) ? x : [x]);

const ensureValuesAreArray = (obj, props = []) =>
  keys(obj).reduce(
    (acc, k) => ({
      ...acc,
      [k]: !props.length || props.includes(k) ? ensureArray(obj[k]) : obj[k],
    }),
    {},
  );

const arraysShareValue = (arr1, arr2, { map = toLower } = {}) =>
  arr1.map(map).some(x => arr2.map(map).includes(x));

const validateAccessRules = ({ url, user, accessRules, valid }) => {
  const rule = reverse(accessRules || [])
    .map(x => ensureValuesAreArray(x, ['route', 'status', 'role']))
    .find(r =>
      [
        r.route.some(x => pathToRegexp(x).exec(url)),
        !r.role || arraysShareValue(r.role, user.roles || []),
        !r.status || arraysShareValue(r.status, [user.status]),
      ].every(Boolean),
    );
  const validity = valid ? 0 : UNAUTHORIZED;
  return rule
    ? rule.type === 'deny' ? FORBIDDEN : rule.tokenExempt ? 0 : validity
    : validity;
};

export default validateAccessRules;
