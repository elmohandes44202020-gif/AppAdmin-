BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,39}$'),
  name TEXT NOT NULL,
  package_name TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  offline_grace_seconds INTEGER NOT NULL DEFAULT 604800 CHECK (offline_grace_seconds BETWEEN 0 AND 2592000),
  freeze_scope TEXT NOT NULL DEFAULT 'generation' CHECK (freeze_scope IN ('generation')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS licenses (
  id UUID PRIMARY KEY,
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT '',
  code_hash BYTEA NOT NULL UNIQUE,
  code_hint TEXT NOT NULL,
  max_installations INTEGER NOT NULL DEFAULT 1 CHECK (max_installations BETWEEN 1 AND 100),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen', 'revoked')),
  message TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS installations (
  id UUID PRIMARY KEY,
  license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  public_id TEXT NOT NULL,
  token_hash BYTEA NOT NULL UNIQUE,
  device_label TEXT,
  device_model TEXT,
  os_version TEXT,
  app_version TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen', 'revoked')),
  message TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (license_id, public_id)
);

CREATE TABLE IF NOT EXISTS activation_requests (
  id UUID PRIMARY KEY,
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  telegram_user_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'delivered', 'cancelled')),
  license_id UUID REFERENCES licenses(id) ON DELETE SET NULL,
  delivery_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  product_id UUID REFERENCES products(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS licenses_product_idx ON licenses(product_id, created_at DESC);
CREATE INDEX IF NOT EXISTS installations_license_idx ON installations(license_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS installations_last_seen_idx ON installations(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS requests_status_idx ON activation_requests(status, created_at ASC);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_request_per_user_product
  ON activation_requests(product_id, telegram_user_id)
  WHERE status = 'pending' AND telegram_user_id IS NOT NULL;

INSERT INTO schema_migrations(version) VALUES ('001_initial') ON CONFLICT DO NOTHING;
COMMIT;
