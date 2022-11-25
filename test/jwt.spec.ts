import {
  FooUserData,
  Identity,
  mockAppToken,
  mockUserToken,
  UserJwtData,
  UserType,
} from '../src/types/jwtDataTypes';
const userStuff = {
  sub: '1234',
  iat: 123,
  exp: 456,
  iss: 'ego',
  jti: 'jti123',
  aud: [],
  context: {
    scope: [''],
    user: {
      email: 'ac',
      status: 'APPROVED',
      firstName: '',
      lastName: '',
      createdAt: 1580931064975,
      lastLogin: 1669299843399,
      preferredLanguage: '',
      providerType: 'GOOGLE',
      providerSubjectId: '',
      type: 'ADMIN' as UserType,
      groups: [],
    },
  },
};
describe('parse jwt types', () => {
  it('should parse', () => {
    // Identity.parse(mockUserToken);
    // Identity.parse(mockAppToken);
    FooUserData.parse(userStuff);
  });
});
