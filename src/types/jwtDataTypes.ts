import * as z from 'zod';

/* Base JWT types */
export const BaseJwtData = z
  .object({
    iat: z.number(),
    exp: z.number(),
    sub: z.string(),
    iss: z.string(),
    jti: z.string(),
  })
  .strict();
export const Scope = z.array(z.string());
export const BaseJwtContext = z
  .object({
    scope: Scope,
  })
  .strict();

export type BaseJwtData = z.infer<typeof BaseJwtData>;
export type BaseJwtContext = z.infer<typeof BaseJwtContext>;
export type Scope = z.infer<typeof Scope>;

/* User JWT data types */
export const UserStatus = z.enum(['APPROVED', 'DISABLED', 'PENDING', 'REJECTED']);
export const UserType = z.enum(['ADMIN', 'USER']);
export const ProviderType = z.enum([
  'GOOGLE',
  'LINKEDIN',
  'FACEBOOK',
  'GITHUB',
  'ORCID',
  'KEYCLOAK',
]);

export const UserJwtContext = z.object({
  context: z.intersection(
    BaseJwtContext,
    z.object({
      user: z.object({
        email: z.string(),
        status: UserStatus,
        firstName: z.string(),
        lastName: z.string(),
        createdAt: z.number(),
        lastLogin: z.number(),
        preferredLanguage: z.optional(z.string()),
        type: UserType,
        providerType: ProviderType,
        providerSubjectId: z.string(),
        groups: z.array(z.string()),
      }),
    }),
  ),
});
export const UserJwtData = UserJwtContext.and(BaseJwtData).and(
  z.object({ aud: z.array(z.string()) }),
);
export const UserIdentity = z.object({
  userId: z.string(),
  tokenInfo: UserJwtData,
});

export type UserStatus = z.infer<typeof UserStatus>;
export type UserType = z.infer<typeof UserType>;
export type ProviderType = z.infer<typeof ProviderType>;
export type UserJwtContext = z.infer<typeof UserJwtContext>;
export type UserJwtData = z.infer<typeof UserJwtData>;
export type UserIdentity = z.infer<typeof UserIdentity>;

/* Application JWT types */
export const ApplicationType = z.enum(['CLIENT', 'ADMIN']);
export const ApplicationStatus = z.enum(['APPROVED', 'DISABLED', 'PENDING', 'REJECTED']);

export const ApplicationJwtContext = z.object({
  context: z.intersection(
    BaseJwtContext,
    z.object({
      application: z.object({
        name: z.string(),
        clientId: z.string(),
        status: ApplicationStatus,
        type: ApplicationType,
        redirectUri: z.optional(z.string()),
        errorRedirectUri: z.optional(z.string()),
      }),
    }),
  ),
});
export const ApplicationJwtData = BaseJwtData.and(
  z.object({
    nbf: z.number(),
    scope: Scope,
  }),
).and(ApplicationJwtContext);
export const ApplicationIdentity = z.intersection(
  z.object({ userId: z.string() }),
  z.object({ tokenInfo: ApplicationJwtData }),
);

export type ApplicationType = z.infer<typeof ApplicationType>;
export type ApplicationStatus = z.infer<typeof ApplicationStatus>;
export type ApplicationJwtContext = z.infer<typeof ApplicationJwtContext>;
export type ApplicationJwtData = z.infer<typeof ApplicationJwtData>;
export type ApplicationIdentity = z.infer<typeof ApplicationIdentity>;

export const Identity = z.union([UserIdentity, ApplicationIdentity]);
export type Identity = z.infer<typeof Identity>;
