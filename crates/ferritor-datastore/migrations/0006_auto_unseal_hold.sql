-- The auto-unseal hold, this database's half (the keys database's
-- auto_unseal_hold keeps the other): an explicit `ferritor seal` raises
-- `hold`, an explicit release (`ferritor unseal --auto`, `--release-hold`)
-- sets `released` to the hold it read, both only ever with GREATEST. A
-- server auto-unseals only if both databases show released >= hold, so
-- undoing an emergency seal takes write access to both databases (or the
-- release).
CREATE TABLE auto_unseal_hold (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    hold       BIGINT NOT NULL DEFAULT 0 CHECK (hold >= 0),
    released   BIGINT NOT NULL DEFAULT 0 CHECK (released >= 0)
);
INSERT INTO auto_unseal_hold DEFAULT VALUES;
