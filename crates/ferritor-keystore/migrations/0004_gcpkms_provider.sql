-- Auto-unseal with Google Cloud KMS: `gcpkms` wraps, keyed by the Cloud KMS
-- key's resource name (projects/…/cryptoKeys/<key>, never a version: decrypt
-- finds the version from the ciphertext). One provider at a time still: a
-- rekey stores its server's wrap and deletes every other, whichever
-- provider made them.
ALTER TABLE seal_wraps
    DROP CONSTRAINT seal_wraps_provider_check,
    ADD CONSTRAINT seal_wraps_provider_check CHECK (provider IN ('awskms', 'gcpkms'));
