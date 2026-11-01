-- Deleting a namespace reclaims its `paths` rows (it has no versions left by
-- then: the server checks), so short-lived paths don't accumulate forever.
-- A version number must never be reused (0001); this keeps that true
-- across the reclaim: the highest version any
-- reclaimed path of the namespace reached is kept here, and a put takes
-- its next version past it too, so a re-created namespace's paths number
-- on from there (a client pinned to an old version never gets a different
-- secret under it). Only raised, by the reclaim; 0 until one.
ALTER TABLE namespaces
    ADD COLUMN version_floor INTEGER NOT NULL DEFAULT 0
        CHECK (version_floor >= 0 AND version_floor < 2147483647);
