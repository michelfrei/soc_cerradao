-- 006: catálogo de atualizações de segurança do Windows Server (MSRC) e publicação
-- do estado de atualização por servidor. Aditiva; aplicada como soc_owner.
ALTER TABLE soc.publication DROP CONSTRAINT publication_entity_check;
ALTER TABLE soc.publication ADD CONSTRAINT publication_entity_check
  CHECK (entity IN ('event', 'incident', 'incident_version', 'alert', 'alert_version', 'device', 'posture', 'insight', 'winupdate'));

-- Um KB por build principal (14393, 17763, 20348…). release_date = primeira
-- publicação conhecida no Security Update Guide; nunca avança para depois.
CREATE TABLE soc.windows_security_update (
    kb              text NOT NULL CHECK (kb ~ '^KB[0-9]+$'),
    build_major     integer NOT NULL,
    product         text NOT NULL,
    fixed_build     text NOT NULL,
    ubr             integer NOT NULL,
    release_date    timestamptz NOT NULL,
    supersedes      text,
    reboot_required boolean,
    url             text,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (kb, build_major)
);
CREATE INDEX windows_security_update_build_idx ON soc.windows_security_update (build_major, ubr);
GRANT SELECT, INSERT, UPDATE ON soc.windows_security_update TO soc_collector;
