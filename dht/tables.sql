CREATE TABLE IF NOT EXISTS ih_info (
    ih BLOB,
    peer_addr BLOB,
    peer_port INTEGER,
    description TEXT,
    last_seen INTEGER,
    PRIMARY KEY(ih, peer_addr, peer_port)
);
