-- Programs can return several results; jobs record each result's type (a JSON
-- array such as '["u8","bool"]'). Jobs from before have one result.
ALTER TABLE jobs ADD COLUMN result_types TEXT NOT NULL DEFAULT '[]';
UPDATE jobs SET result_types = json_array(result_type);

-- Results returned as one compressed list instead of a ciphertext each.
ALTER TABLE jobs ADD COLUMN compressed_results INTEGER NOT NULL DEFAULT 0;

-- Keys made with compression keys (the SDK's compressing configuration).
ALTER TABLE server_keys ADD COLUMN supports_compression INTEGER NOT NULL DEFAULT 0;
