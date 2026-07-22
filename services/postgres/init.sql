-- Agent Policy Gateway Database Schema
-- Used by auth-service (users) and gateway (audit log)

-- Users table (for auth service)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    workspace VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'operator',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
);

-- Audit events table (append-only)
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    correlation_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    caller_identity VARCHAR(64),
    method VARCHAR(100),
    params_redacted JSONB,
    outcome VARCHAR(10) NOT NULL CHECK (outcome IN ('ALLOW', 'DENY')),
    denial_reason TEXT,
    rule_matched TEXT,
    role_assumed TEXT,
    duration_ms DOUBLE PRECISION,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for fast audit queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_events(outcome);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_events(correlation_id);

-- Pipeline stats table
CREATE TABLE IF NOT EXISTS pipeline_stats (
    stage VARCHAR(50) PRIMARY KEY,
    pass_count BIGINT DEFAULT 0,
    fail_count BIGINT DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Initialize pipeline stages
INSERT INTO pipeline_stats (stage) VALUES
    ('Agent Auth'), ('Schema Valid'), ('Policy Eval'),
    ('Egress Ctrl'), ('Quota Check'), ('STS Mint'),
    ('Execute'), ('Resp Filter'), ('Audit Log'), ('Return')
ON CONFLICT (stage) DO NOTHING;

-- Policy history (track policy changes)
CREATE TABLE IF NOT EXISTS policy_history (
    id BIGSERIAL PRIMARY KEY,
    policy_hash VARCHAR(100) NOT NULL,
    policy_json JSONB NOT NULL,
    loaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    loaded_by VARCHAR(100)
);

-- No default operator account is seeded (no shipped credentials).
-- Operator auth is configured via environment variables:
--   APG_OPERATOR_EMAIL / APG_OPERATOR_WORKSPACE and an argon2
--   APG_OPERATOR_PASSWORD_HASH (generate with `apg hash-password`).
-- If you later persist operators in this table, store only argon2 hashes.
