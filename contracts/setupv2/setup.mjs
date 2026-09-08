// Public contract validation only. Callers must separately authenticate signed
// artifacts, release provenance, ownership, and the current website revision.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import Ajv from "ajv/dist/2020.js";
import canonicalize from "canonicalize";

export const MAX_BYTES = 8 * 1024 * 1024;
export const schema = JSON.parse(readFileSync(new URL("./schema.json", import.meta.url)));
export const ruleset = JSON.parse(readFileSync(new URL("./ruleset.json", import.meta.url)));
const beaconProfile = JSON.parse(readFileSync(new URL("./beacon.json", import.meta.url)));
export const beacon = mode => ({ ...beaconProfile, minimum_witness_lead_seconds: mode === "production" ? 86400 : 180 });
const validateSchema = new Ajv({ strict: false, allErrors: false }).compile(schema);
export const hash = bytes => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
export const canonical = value => canonicalize(value);
export const digest = (domain, value) => hash(`${domain}\n${canonical(value)}`);
export const rules = () => ({ id: ruleset.id, version: ruleset.version, sha256: hash(canonical(ruleset)) });
export const inputDigest = ({ schema, id, plan_revision, plan }) => digest("ceremony-setup-input-v2", { schema, id, plan_revision, plan });
export const resultDigest = result => digest("ceremony-setup-result-v2", result);
export const setupDigest = setup => digest("ceremony-setup-v2", setup);
const require = (condition, message) => { if (!condition) throw new Error(message); };

export function parseStrict(bytes) {
  const raw = Buffer.from(bytes);
  require(raw.length <= MAX_BYTES, "Setup exceeds 8 MiB");
  const text = raw.toString("utf8");
  require(Buffer.from(text).equals(raw), "Setup is not UTF-8");
  let i = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(text[i] || "")) i++; };
  const string = () => {
    require(text[i] === '"', "Invalid JSON string");
    const start = i++;
    while (i < text.length) {
      if (text[i] === "\\") { i += 2; continue; }
      if (text[i++] === '"') {
        const value = JSON.parse(text.slice(start, i));
        require(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value), "Invalid Unicode surrogate");
        return value;
      }
    }
    throw new Error("Unterminated JSON string");
  };
  const value = depth => {
    ws(); require(depth <= 16, "JSON nesting exceeds 16");
    if (text[i] === '{') {
      require(depth < 16, "JSON nesting exceeds 16");
      i++; ws(); const keys = new Set();
      if (text[i] === '}') { i++; return; }
      while (true) {
        ws(); const key = string(); require(!keys.has(key), "Duplicate JSON key"); keys.add(key);
        ws(); require(text[i++] === ':', "Invalid JSON object"); value(depth + 1); ws();
        if (text[i] === '}') { i++; return; } require(text[i++] === ',', "Invalid JSON object");
      }
    }
    if (text[i] === '[') {
      require(depth < 16, "JSON nesting exceeds 16");
      i++; ws(); if (text[i] === ']') { i++; return; }
      while (true) { value(depth + 1); ws(); if (text[i] === ']') { i++; return; } require(text[i++] === ',', "Invalid JSON array"); }
    }
    if (text[i] === '"') { string(); return; }
    const start = i; while (i < text.length && !/[\x20\t\r\n,}\]]/.test(text[i])) i++;
    require(i > start, "Invalid JSON value");
  };
  value(0); ws(); require(i === text.length, "Trailing JSON data");
  return JSON.parse(text);
}

export function parseSetup(bytes) {
  const setup = parseStrict(bytes);
  require(validateSchema(setup), `Setup schema: ${validateSchema.errors?.[0]?.instancePath || "/"} ${validateSchema.errors?.[0]?.message || "invalid"}`);
  const p = setup.plan;
  require(canonical(p.beacon_policy) === canonical(beacon(p.mode)), "Beacon policy must match the approved profile for this mode");
  require(canonical(p.ruleset) === canonical(rules()), "Unsupported ruleset digest");
  require(p.mode !== "production" || p.circuit !== "rehearsal-tiny-v1", "Tiny circuit is rehearsal only");
  require(p.software_release.release_tag === `role-images-${p.software_release.cli_commit}`, "Release tag does not match CLI commit");
  require(p.storage.published_bucket !== p.storage.inbox_bucket, "Published and inbox buckets must differ");
  const u = new URL(p.storage.public_base_url);
  require(!/%(?![0-9A-Fa-f]{2})/.test(p.storage.public_base_url), "Invalid public URL escape");
  require(p.storage.public_base_url.startsWith("https://") && u.protocol === "https:" && u.hostname && !u.username && !u.password && !/[?#\\\r\n\t ]/.test(p.storage.public_base_url), "Public storage URL must be HTTPS without credentials, query or fragment");
  require(p.mode !== "production" || p.beacon_policy.minimum_witness_lead_seconds >= 86400, "Production witness lead must be at least 86400 seconds");
  const ids = new Set(), keys = new Set(), keyIDs = new Set();
  for (const identity of p.identities) {
    require(!ids.has(identity.id) && !keys.has(identity.ed25519_public_key_hex) && !keyIDs.has(identity.key_id), "Each identity must have a distinct ID, key ID and public key");
    ids.add(identity.id); keys.add(identity.ed25519_public_key_hex); keyIDs.add(identity.key_id);
    require(hash(Buffer.from(identity.ed25519_public_key_hex, "hex")) === identity.public_key_fingerprint, `Identity ${identity.id} fingerprint does not match its public key`);
  }
  const used = new Set(), roles = new Set(), counts = new Map(), participants = new Set();
  for (const r of p.roles) {
    require(!roles.has(r.id) && !used.has(r.identity_id) && ids.has(r.identity_id), "Each role must have a distinct ID and assigned identity");
    roles.add(r.id); used.add(r.identity_id); counts.set(r.role, (counts.get(r.role) || 0) + 1);
    if (r.role === "participant") participants.add(r.identity_id);
  }
  require(used.size === ids.size, "Unassigned public identity");
  require(counts.get("coordinator") === 1 && counts.get("release-signer") === 1 && counts.get("auditor") >= 2, "Setup requires one coordinator, one release signer and at least two auditors");
  const phases = new Set(), scheduled = new Set();
  for (const phase of p.phases) {
    require(!phases.has(phase.id), "Duplicate phase"); phases.add(phase.id);
    require(phase.minimum <= phase.identity_ids.length, "Phase minimum exceeds its participants");
    require(p.mode !== "production" || (phase.identity_ids.length >= 2 && phase.minimum === phase.identity_ids.length), "Production requires at least two participants and all contributions per phase");
    for (const id of phase.identity_ids) { require(participants.has(id), "Phase member is not a participant"); scheduled.add(id); }
  }
  require(scheduled.size === participants.size, "Each participant must be in at least one phase");
  if (setup.result) {
    require(setup.result.input_sha256 === inputDigest(setup), "Result belongs to a different setup plan");
    const found = new Set();
    for (const a of setup.result.artifacts) {
      const key = `${a.kind}:${a.platform}`; require(!found.has(key), "Duplicate artifact"); found.add(key);
      require((a.kind === "tool-receipt") !== (a.platform === "none"), "Invalid artifact platform");
      const b = Buffer.from(a.content_b64, "base64");
      require(b.toString("base64") === a.content_b64 && b.length === a.byte_length && hash(b) === a.sha256, `Artifact ${a.kind} bytes do not match length or digest`);
      require(a.kind !== "software-manifest" || a.sha256 === p.software_release.manifest_sha256, "Software manifest differs from selected release");
    }
    for (const kind of ["definition", "definition-signature", "coordinator-key", "software-manifest"]) require(found.has(`${kind}:none`), `Missing ${kind} artifact`);
  }
  return setup;
}
