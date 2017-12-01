/* TABLES */
CREATE TABLE IF NOT EXISTS metainfo (
    info_hash   BINARY(20)       NOT NULL,
    description VARBINARY(256),
    flag        TINYINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (info_hash)
);


CREATE TABLE IF NOT EXISTS peerinfo (
    info_hash BINARY(20) NOT NULL,
    addr_port BINARY(6)  NOT NULL,
    timestamp TIMESTAMP  NOT NULL,
    PRIMARY KEY (info_hash, addr_port),
    CONSTRAINT `legal_ih`
        FOREIGN KEY (info_hash) REFERENCES metainfo (info_hash)
        ON DELETE CASCADE
        ON UPDATE RESTRICT
);

/* XXX THIS IS SLOW

CREATE VIEW IF NOT EXISTS peerinfo_latest AS
    SELECT
        `info_hash`, MAX(`timestamp`) AS `timestamp`
    FROM
        `peerinfo`
    GROUP BY
        `info_hash`
    ;
*/

/* INDEXES */
CREATE TABLE IF NOT EXISTS cand_ihashes (
    info_hash BINARY(20)    NOT NULL,
    PRIMARY KEY (info_hash)
) ENGINE = MEMORY;


CREATE INDEX IF NOT EXISTS ix_scratch
    ON cand_ihashes (info_hash)
    USING HASH;


/* CREATE INDEX IF NOT EXISTS ix_peer_time
    ON peerinfo (timestamp)
    USING BTREE; */


/* FIXME TRIGGERS */
