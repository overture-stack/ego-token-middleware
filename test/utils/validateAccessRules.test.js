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
        route: [`/a/graphql`, `/b/download`],
        status: ['approved'],
        role: 'user',
      },
    ];

    test('deny root from role', () =>
      expect(
        validateAccessRules({
          url: '/',
          user: { roles: ['user'] },
          accessRules: ruleSetOne,
        }),
      ).toEqual(false));

    test('deny non-root from role', () =>
      expect(
        validateAccessRules({
          url: '/abcd',
          user: { roles: ['user'] },
          accessRules: ruleSetOne,
        }),
      ).toEqual(false));

    test('deny non-root from status', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'pending' },
          accessRules: ruleSetOne,
        }),
      ).toEqual(false));

    test('allow non-root from status', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'approved' },
          accessRules: ruleSetOne,
        }),
      ).toEqual(true));

    test('allow non-root from role', () =>
      expect(
        validateAccessRules({
          url: '/asfdk',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
        }),
      ).toEqual(true));

    test('allow non-root from role', () =>
      expect(
        validateAccessRules({
          url: '/asfdk',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
        }),
      ).toEqual(true));
  });
});
