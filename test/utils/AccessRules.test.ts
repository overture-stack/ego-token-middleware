import { expect } from 'chai';
import { FORBIDDEN, UNAUTHORIZED, validateAccessRules } from '../../src/utils/validateAccessRules';

describe('validateAccessRules', () => {

  describe('ruleSetOne', () => {
    const ruleSetOne = () => [
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
        route: ['/(.*)/graphql', '/(.*)/graphql/(.*)', '/(.*)/download'],
        status: ['approved'],
        role: 'user',
      },
      {
        type: 'allow',
        route: ['/(.*)/ping'],
        tokenExempt: true,
      },
    ];

    it('deny root from role', () => {
      expect(
        validateAccessRules('/', { roles: ['user'] }, ruleSetOne(), false)
      ).to.equal(FORBIDDEN);
    });

    it('deny non-root from role', () => {
      expect(
        validateAccessRules('/abcd', { roles: ['user'] }, ruleSetOne(), false)
      ).to.equal(FORBIDDEN);
    });

    it('deny non-root from status', () => {
      expect(
        validateAccessRules('/a/graphql', { roles: ['user'], status: 'pending' }, ruleSetOne(), false)
      ).to.equal(FORBIDDEN);
    });

    it('when user is not yet approved', () => {
      expect(
        validateAccessRules('/a/graphql', { roles: ['user'], status: 'pending' }, ruleSetOne(), true)
      ).to.equal(FORBIDDEN);
    });

    it('allow non-root from status', () => {
      expect(
        validateAccessRules('/a/graphql', { roles: ['user'], status: 'approved' }, ruleSetOne(), true)
      ).to.equal(0);
    });

    it('when token is invalid', () => {
      expect(
        validateAccessRules('/a/graphql', { roles: ['user'], status: 'approved' }, ruleSetOne(), false)
      ).to.equal(UNAUTHORIZED);
    });

    it('allow non-root from status with gql extension', () => {
      expect(
        validateAccessRules('/a/graphql/abcd', { roles: ['user'], status: 'approved' }, ruleSetOne(), true)
      ).to.equal(0);
    });

    it('allow non-root from status with wildcard', () => {
      expect(
        validateAccessRules('/fdlkj/download', { roles: ['USER'], status: 'Approved' }, ruleSetOne(), true)
      ).to.equal(0);
    });

    it('allow root from role', () => {
      expect(
        validateAccessRules('/', { roles: ['admin'], status: 'rejected' }, ruleSetOne(), true)
      ).to.equal(0);
    });

    it('allow non-root from role', () => {
      expect(
        validateAccessRules('/asfdk', { roles: ['admin'], status: 'rejected' }, ruleSetOne(), true)
      ).to.equal(0);
    });

    it('ignore invalid token if tokenExempt', () => {
      expect(
        validateAccessRules('/asd/ping', { roles: ['admin'], status: 'rejected' }, ruleSetOne(), false)
      ).to.equal(0);
    });

  });

});