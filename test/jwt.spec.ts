import { ApplicationJwtData, Identity, UserJwtData } from '../src/types';

export const mockUserToken = {
  userId: '1234',
  tokenInfo: {
    sub: '1234',
    iat: 123,
    exp: 456,
    iss: 'ego',
    jti: 'jti123',
    aud: [],
    context: {
      scope: [''],
      user: {
        email: 'a',
        status: 'APPROVED',
        firstName: 'A',
        lastName: 'C',
        createdAt: 1580931064975,
        lastLogin: 1669299843399,
        preferredLanguage: '',
        providerType: 'GOOGLE',
        providerSubjectId: '123',
        type: 'ADMIN',
        groups: [],
      },
    },
  },
};

export const mockAppToken = {
  userId: '0b8',
  tokenInfo: {
    sub: '0b8',
    exp: 1670087158,
    iat: 1669223158,
    jti: '14',
    nbf: 1669223158,
    scope: [''],
    iss: 'ego',
    context: {
      scope: [''],
      application: {
        name: '',
        clientId: '',
        redirectUri: '',
        status: 'APPROVED',
        errorRedirectUri: '',
        type: 'CLIENT',
      },
    },
  },
};
const userData = {
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
      type: 'ADMIN',
      groups: [],
    },
  },
};

const appData = {
  sub: '0b8',
  exp: 1670087158,
  iat: 1669223158,
  jti: '14',
  nbf: 1669223158,
  scope: [''],
  iss: 'ego',
  context: {
    scope: [''],
    application: {
      name: '',
      clientId: '',
      redirectUri: '',
      status: 'APPROVED',
      errorRedirectUri: '',
      type: 'CLIENT',
    },
  },
};

describe('parse jwt types', () => {
  it('should parse a token', () => {
    Identity.parse(mockUserToken);
    Identity.parse(mockAppToken);
  });

  it('should parse data by type', () => {
    UserJwtData.parse(userData);
    ApplicationJwtData.parse(appData);
  });
});