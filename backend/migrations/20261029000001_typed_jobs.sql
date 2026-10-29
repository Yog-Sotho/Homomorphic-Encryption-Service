-- Jobs on several integer types, with plaintext (scalar) operands, sums over
-- many inputs and zero-knowledge-proven inputs. Existing jobs are two FheUint16
-- ciphertexts with no scalar, which the defaults describe.
ALTER TABLE jobs ADD COLUMN integer_type TEXT NOT NULL DEFAULT 'u16';
ALTER TABLE jobs ADD COLUMN result_type TEXT NOT NULL DEFAULT 'u16';
-- Encrypted inputs. A proven job stores one list file holding all of them.
ALTER TABLE jobs ADD COLUMN input_count INTEGER NOT NULL DEFAULT 2;
ALTER TABLE jobs ADD COLUMN proven INTEGER NOT NULL DEFAULT 0;
-- The plaintext right-hand operand, in decimal. The client chose to reveal it.
ALTER TABLE jobs ADD COLUMN scalar TEXT;

-- Keys made with the compact-public-key parameters can take proven inputs once
-- their public key (<id>.pk in the key store) is uploaded.
ALTER TABLE server_keys ADD COLUMN supports_proofs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE server_keys ADD COLUMN public_key_sha256 TEXT;
