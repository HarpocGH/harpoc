import { z } from "zod";

import { MAX_NAME_LENGTH } from "./constants.js";
import { isValidHandle } from "./handle.js";
import {
  AuditEventType,
  FollowRedirects,
  InjectionType,
  OAuthGrantType,
  OAuthProviderPreset,
  Permission,
  PrincipalType,
  SecretStatus,
  SecretType,
} from "./types.js";

// ---------------------------------------------------------------------------
// Enum schemas (derived from const objects in types.ts)
// ---------------------------------------------------------------------------

const secretTypeValues = Object.values(SecretType) as [SecretType, ...SecretType[]];
export const secretTypeSchema = z.enum(secretTypeValues);

const secretStatusValues = Object.values(SecretStatus) as [SecretStatus, ...SecretStatus[]];
export const secretStatusSchema = z.enum(secretStatusValues);

const permissionValues = Object.values(Permission) as [Permission, ...Permission[]];
export const permissionSchema = z.enum(permissionValues);

const auditEventTypeValues = Object.values(AuditEventType) as [AuditEventType, ...AuditEventType[]];
export const auditEventTypeSchema = z.enum(auditEventTypeValues);

const principalTypeValues = Object.values(PrincipalType) as [PrincipalType, ...PrincipalType[]];
export const principalTypeSchema = z.enum(principalTypeValues);

const injectionTypeValues = Object.values(InjectionType) as [InjectionType, ...InjectionType[]];
export const injectionTypeSchema = z.enum(injectionTypeValues);

const followRedirectsValues = Object.values(FollowRedirects) as [
  FollowRedirects,
  ...FollowRedirects[],
];
export const followRedirectsSchema = z.enum(followRedirectsValues);

// ---------------------------------------------------------------------------
// Handle schema
// ---------------------------------------------------------------------------

export const handleSchema = z.string().refine(isValidHandle, { message: "Invalid secret handle" });

// ---------------------------------------------------------------------------
// Injection config schema
// ---------------------------------------------------------------------------

export const injectionConfigSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal(InjectionType.BEARER) }),
  z.object({ type: z.literal(InjectionType.BASIC_AUTH) }),
  z.object({
    type: z.literal(InjectionType.HEADER),
    header_name: z
      .string()
      .min(1)
      .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid header name characters"),
  }),
  z.object({
    type: z.literal(InjectionType.QUERY),
    query_param: z.string().min(1),
  }),
]);

// ---------------------------------------------------------------------------
// Input validation schemas (API boundaries: REST bodies, MCP inputs, CLI args)
// ---------------------------------------------------------------------------

const namePattern = z
  .string()
  .regex(/^[a-zA-Z0-9_-]+$/, "Invalid name format")
  .max(MAX_NAME_LENGTH);

export const createSecretInputSchema = z.object({
  name: namePattern,
  type: secretTypeSchema,
  project: namePattern.optional(),
  injection: injectionConfigSchema.optional(),
});

export const httpMethodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);

export const useSecretRequestSchema = z.object({
  handle: handleSchema,
  request: z.object({
    method: httpMethodSchema,
    url: z.string().url(),
    headers: z.record(z.string()).optional(),
    body: z.string().optional(),
    timeout_ms: z.number().int().positive().max(300_000).optional(),
  }),
  injection: injectionConfigSchema,
  follow_redirects: followRedirectsSchema.optional(),
});

export const accessPolicyInputSchema = z.object({
  principal_type: principalTypeSchema,
  principal_id: z.string().min(1),
  permissions: z.array(permissionSchema).min(1),
  expires_at: z.number().int().positive().optional(),
});

export const auditQuerySchema = z.object({
  secret_id: z.string().uuid().optional(),
  event_type: auditEventTypeSchema.optional(),
  since: z.number().int().nonnegative().optional(),
  until: z.number().int().nonnegative().optional(),
  limit: z.number().int().positive().max(1000).optional(),
});

// ---------------------------------------------------------------------------
// Session file schema (for deserializing session.json)
// ---------------------------------------------------------------------------

const base64Pattern = z.string().min(1).base64();

export const sessionFileSchema = z.object({
  version: z.literal(1),
  session_id: z.string().min(1),
  vault_id: z.string().min(1),
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  max_expires_at: z.number().int().positive(),
  session_key: base64Pattern,
  wrapped_kek: base64Pattern,
  wrapped_kek_iv: base64Pattern,
  wrapped_kek_tag: base64Pattern,
  wrapped_jwt_key: base64Pattern,
  wrapped_jwt_key_iv: base64Pattern,
  wrapped_jwt_key_tag: base64Pattern,
  wrapped_audit_key: base64Pattern,
  wrapped_audit_key_iv: base64Pattern,
  wrapped_audit_key_tag: base64Pattern,
});

// ---------------------------------------------------------------------------
// OAuth schemas (v1.1)
// ---------------------------------------------------------------------------

const oauthGrantTypeValues = Object.values(OAuthGrantType) as [OAuthGrantType, ...OAuthGrantType[]];
export const oauthGrantTypeSchema = z.enum(oauthGrantTypeValues);

const oauthProviderPresetValues = Object.values(OAuthProviderPreset) as [
  OAuthProviderPreset,
  ...OAuthProviderPreset[],
];
export const oauthProviderPresetSchema = z.enum(oauthProviderPresetValues);

const httpsUrlSchema = z.string().url().startsWith("https://", "URL must use HTTPS");

export const oauthProviderConfigSchema = z
  .object({
    provider: oauthProviderPresetSchema,
    grant_type: oauthGrantTypeSchema,
    token_endpoint: httpsUrlSchema,
    auth_endpoint: httpsUrlSchema.optional(),
    device_authorization_endpoint: httpsUrlSchema.optional(),
    client_id: z.string().min(1),
    client_secret: z.string().min(1).optional(),
    scopes: z.array(z.string().min(1)).optional(),
    redirect_uri: z.string().url().optional(),
    pkce_method: z.literal("S256").optional(),
  })
  .superRefine((data, ctx) => {
    if (data.grant_type === OAuthGrantType.AUTHORIZATION_CODE && !data.auth_endpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "auth_endpoint is required for authorization_code grant type",
        path: ["auth_endpoint"],
      });
    }
    if (data.grant_type === OAuthGrantType.DEVICE_CODE && !data.device_authorization_endpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "device_authorization_endpoint is required for device_code grant type",
        path: ["device_authorization_endpoint"],
      });
    }
  });

export const startOAuthFlowInputSchema = z.object({
  name: namePattern,
  provider: oauthProviderPresetSchema,
  grant_type: oauthGrantTypeSchema,
  client_id: z.string().min(1),
  client_secret: z.string().min(1).optional(),
  scopes: z.array(z.string().min(1)).optional(),
  project: namePattern.optional(),
  auth_endpoint: httpsUrlSchema.optional(),
  token_endpoint: httpsUrlSchema.optional(),
  device_authorization_endpoint: httpsUrlSchema.optional(),
});

// ---------------------------------------------------------------------------
// Certificate schemas (v1.1)
// ---------------------------------------------------------------------------

const pemPattern = z
  .string()
  .min(1)
  .refine((s) => s.startsWith("-----BEGIN "), "Value must be PEM-encoded");

export const certificateImportSchema = z.object({
  name: namePattern,
  private_key_pem: pemPattern,
  certificate_pem: pemPattern.optional(),
  chain_pem: pemPattern.optional(),
  project: namePattern.optional(),
  auto_renew: z.boolean().optional().default(false),
  renew_before_days: z.number().int().positive().max(365).optional().default(30),
});
