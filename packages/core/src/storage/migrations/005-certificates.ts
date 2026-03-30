import { CREATE_CERTIFICATES, CREATE_CERTIFICATES_INDEXES } from "../schema.js";

export const migration005 = {
  version: 5,
  up: [CREATE_CERTIFICATES, CREATE_CERTIFICATES_INDEXES].join("\n"),
};
