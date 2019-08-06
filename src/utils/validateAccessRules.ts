import { reverse } from 'lodash/fp';
import pathToRegexp from 'path-to-regexp';

type AccessRule = {
  type: string
  route: Array<string>
  status?: Array<string>
  role?: Array<string>
  tokenExempt?: boolean
} | { [key: string]: any };


export const UNAUTHORIZED = { code: 401, message: 'unauthorized' };
export const FORBIDDEN = { code: 403, message: 'forbidden' };

const toLower = (x: string) => (x || '').toLowerCase();

const ensureArray = (x: any) => (Array.isArray(x) ? x : [x]);

/**
 * Mutation of object to ensure values are arrays, returns modified objected
 * @param obj AccessRule object
 * @param props which properties to check
 */
const ensureValuesAreArray = (obj: AccessRule): AccessRule => {
  if (obj.route) obj.route = ensureArray(obj.route);
  if (obj.status) obj.status = ensureArray(obj.status);
  if (obj.role) obj.role = ensureArray(obj.role);
  return obj;
};

const arraysShareValue = (arr1: Array<string>, arr2: Array<string>, { map = toLower } = {}) =>
  arr1.map(map).some(x => arr2.map(map).includes(x));

const validateAccessRules = (url: string, user: any, accessRules: Array<AccessRule>, valid: boolean) => {
  const rule: AccessRule = reverse(accessRules || [])
    .map((x: AccessRule) => ensureValuesAreArray(x))
    .find((r: AccessRule): Boolean =>
      [
        r.route.some((x: string) => pathToRegexp(x).exec(url)),
        (r.role === undefined) || arraysShareValue(r.role, user.roles || []),
        (r.status === undefined) || arraysShareValue(r.status, [user.status]),
      ].every(Boolean));

  const validity = valid ? 0 : UNAUTHORIZED;
  return rule
    ? rule.type === 'deny' ? FORBIDDEN : rule.tokenExempt ? 0 : validity
    : validity;
};

export default validateAccessRules;
