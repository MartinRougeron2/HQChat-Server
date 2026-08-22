-- Durable tier: what the system would be wrong without. Replicated to any read
-- replica a later region gets; backed up by DigitalOcean's PITR.

-- Case-insensitive text, so `Helper` and `helper` cannot both be claimed.
CREATE EXTENSION IF NOT EXISTS citext;

-- ============================================================
-- 1. IDENTITY
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  pk         text PRIMARY KEY,
  -- UNIQUE is the whole point: the Redis version did SISMEMBER then a
  -- non-atomic pipeline, so two simultaneous registrations could both pass the
  -- check and both write. A constraint cannot be raced.
  --
  -- citext also closes a gap the Redis shape had: `username:{u}` was a
  -- case-SENSITIVE key while the reserved-handle blacklist lowercased, so
  -- `Helper` was claimable while `helper` was not.
  username   citext UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  tier       text NOT NULL DEFAULT 'free'
);

-- ============================================================
-- 2. SOCIAL GRAPH
-- ============================================================
-- One row per friendship, not two sets plus a blind hash plus a members set.
-- The pair is normalised (pk_lo < pk_hi) so "are these two friends" is a primary
-- key lookup from either direction.
--
-- COLLATE "C" on the CHECK is load-bearing: JavaScript's Array.sort() compares
-- UTF-16 code units, and lib/crypto-utils.ts sorts the pair that way before
-- hashing it. Any other collation and Postgres would disagree with the hash.
CREATE TABLE IF NOT EXISTS friendships (
  pk_lo      text NOT NULL,
  pk_hi      text NOT NULL,
  -- sha256(pk_lo || pk_hi), written by the application. Deliberately NOT a
  -- generated column: friendshipHash() has a Swift counterpart and a cross-impl
  -- test vector, and it should keep exactly one definition.
  hash       text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (pk_lo, pk_hi),
  CHECK (pk_lo COLLATE "C" < pk_hi COLLATE "C")
);
CREATE INDEX IF NOT EXISTS friendships_pk_hi_idx ON friendships (pk_hi);

-- An invite lives in the recipient's inbox, keyed by the sender — same shape as
-- `invites:{to}` was. The index on from_pk is what replaces deleteUser's SCAN
-- over every inbox in the system.
CREATE TABLE IF NOT EXISTS invites (
  to_pk      text NOT NULL,
  from_pk    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (to_pk, from_pk)
);
CREATE INDEX IF NOT EXISTS invites_from_pk_idx ON invites (from_pk);

-- ============================================================
-- 3. PUSH
-- ============================================================
CREATE TABLE IF NOT EXISTS push_tokens (
  pk         text PRIMARY KEY,
  platform   text NOT NULL DEFAULT 'ios',
  token      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- ============================================================
-- 4. SUBSCRIPTIONS
-- ============================================================
-- A subscription is bought on the website and claimed from the app, joined by an
-- email address this server never stores: it exists here only as
-- H = sha256(lowercased email). A dump of this database says which subscriptions
-- exist, not whose.
CREATE TABLE IF NOT EXISTS subscriptions (
  email_hash  text PRIMARY KEY,
  state       text NOT NULL CHECK (state IN ('waiting', 'active', 'cancelled')),
  customer_id text,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Reverse index, so a Stripe webhook carrying only a customer id resolves
-- without an API call back to Stripe.
CREATE TABLE IF NOT EXISTS subscription_customers (
  customer_id text PRIMARY KEY,
  email_hash  text NOT NULL
);

-- Which device keys have claimed a subscription. Devices are recorded by RAW
-- public key: revoking a lapsed subscriber means editing mqtt_acl and kicking
-- {pk} off the broker, and a blinded key can address neither.
CREATE TABLE IF NOT EXISTS subscription_claims (
  pk         text PRIMARY KEY,
  email_hash text NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS subscription_claims_email_hash_idx
  ON subscription_claims (email_hash);

-- ============================================================
-- 5. ADMISSION
-- ============================================================
-- Self-registered exemptions. The helper bot writes its own pk here at startup,
-- so it is admitted under any policy without an operator hand-copying a key that
-- goes stale whenever the bot's identity changes.
CREATE TABLE IF NOT EXISTS admission_exempt (
  pk text PRIMARY KEY
);

-- ============================================================
-- 6. MQTT AUTHORIZATION
-- ============================================================
-- EMQX reads this directly, once per client-topic per authz-cache window. Kept
-- materialised rather than a view over `friendships` because a view would join
-- on every cache miss.
--
-- The topic name is derivable by anyone who knows both public keys, so
-- authorization rests ENTIRELY on this table — never on topic-name secrecy.
CREATE TABLE IF NOT EXISTS mqtt_acl (
  pk     text NOT NULL,
  topic  text NOT NULL,
  action text NOT NULL CHECK (action IN ('publish', 'subscribe', 'all')),
  PRIMARY KEY (pk, topic)
);

-- The one table the broker's role may read (see 000_roles.sql).
GRANT SELECT ON mqtt_acl TO ${EMQX_ROLE};

-- Tables created above predate the ALTER DEFAULT PRIVILEGES only when this
-- migration is re-run against an older database; granting explicitly is
-- idempotent and covers both orders.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};
