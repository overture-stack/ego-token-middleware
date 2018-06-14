import { validateAccessRules } from '../../src/utils';

describe('validateAccessRules', () => {
  describe('ruleSetOne', () => {
    const ruleSetOne = [
      {
        type: 'allow',
        route: ['/', '/(.*)'],
        role: 'admin',
      },
      {
        type: 'deny',
        route: ['/', '/(.*)'],
        role: ['user'],
      },
      {
        type: 'allow',
        route: [`/(.*)/graphql`, `/(.*)/graphql/(.*)`, `/(.*)/download`],
        status: ['approved'],
        role: 'user',
      },
      {
        type: 'allow',
        route: [`/(.*)/ping`],
        tokenExempt: true,
      },
    ];

    test('deny root from role', () =>
      expect(
        validateAccessRules({
          url: '/',
          user: { roles: ['user'] },
          accessRules: ruleSetOne,
        }),
      ).toEqual(403));

    test('deny non-root from role', () =>
      expect(
        validateAccessRules({
          url: '/abcd',
          user: { roles: ['user'] },
          accessRules: ruleSetOne,
        }),
      ).toEqual(403));

    test('deny non-root from status', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'pending' },
          accessRules: ruleSetOne,
        }),
      ).toEqual(403));

    test('when token is invalid', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'pending' },
          accessRules: ruleSetOne,
          valid: false,
        }),
      ).toEqual(403));

    test('allow non-root from status', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'approved' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('when token is invalid', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'approved' },
          accessRules: ruleSetOne,
          valid: false,
        }),
      ).toEqual(401));

    test('allow non-root from status with gql extension', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql/abcd',
          user: { roles: ['user'], status: 'approved' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('allow non-root from status with wildcard', () =>
      expect(
        validateAccessRules({
          url: '/fdlkj/download',
          user: { roles: ['USER'], status: 'Approved' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('allow root from role', () =>
      expect(
        validateAccessRules({
          url: '/',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('allow non-root from role', () =>
      expect(
        validateAccessRules({
          url: '/asfdk',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('ignore invalid token if tokenExempt', () =>
      expect(
        validateAccessRules({
          url: '/asd/ping',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
          valid: false,
        }),
      ).toEqual(0));
  });
});
