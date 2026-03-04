import { ALTER_SECRETS_ADD_NAME_HMAC, CREATE_NAME_HMAC_INDEX } from "../schema.js";

export const migration003 = {
  version: 3,
  up: [ALTER_SECRETS_ADD_NAME_HMAC, CREATE_NAME_HMAC_INDEX].join("\n"),
};
