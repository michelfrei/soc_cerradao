-- 002: manutenção segura da publicação (achados da revisão independente).
--  * purge_publication passa a exigir o txid já confirmado pelo Logstash, para
--    não apagar o que ainda não foi indexado.
--  * republish_events vira procedimento que confirma uma fatia por vez, para que
--    uma reindexação grande não gere uma transação gigante no Logstash.
--  * republish_objects republica o estado atual e as versões de incidentes/alertas.

DROP FUNCTION soc.purge_publication(interval);

-- p_logstash_txid: valor de /srv/soc/logstash-data/soc_publication_last_run.yml.
CREATE FUNCTION soc.purge_publication(p_logstash_txid bigint, p_keep interval DEFAULT interval '7 days')
RETURNS bigint
LANGUAGE sql
SET search_path = pg_catalog, soc
AS $$
    WITH del AS (
        DELETE FROM soc.publication
        WHERE created_at < now() - p_keep
          AND txid <= (p_logstash_txid)::text::xid8
        RETURNING 1
    )
    SELECT count(*) FROM del;
$$;
REVOKE ALL ON FUNCTION soc.purge_publication(bigint, interval) FROM PUBLIC;

DROP FUNCTION soc.republish_events(text, timestamptz, timestamptz);

-- Uso (fora de transação): CALL soc.republish_events('DeviceLogonEvents', '2026-10-01', '2026-10-08');
CREATE PROCEDURE soc.republish_events(
    p_table text, p_from timestamptz, p_to timestamptz, p_slice interval DEFAULT interval '1 day')
LANGUAGE plpgsql
-- Sem cláusula SET: o PostgreSQL proíbe COMMIT em procedimentos que a usam.
-- Todos os objetos estão qualificados com o schema.
AS $$
DECLARE
    s timestamptz := p_from;
    e timestamptz;
    n bigint;
BEGIN
    IF p_to <= p_from OR p_slice <= interval '0' THEN
        RAISE EXCEPTION 'intervalo inválido: % a % (fatia %)', p_from, p_to, p_slice;
    END IF;
    WHILE s < p_to LOOP
        e := least(s + p_slice, p_to);
        INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
        SELECT 'event', lower(r.table_name), r.event_key, r.occurred_at, r.payload
        FROM soc.raw_event r
        WHERE r.table_name = p_table AND r.occurred_at >= s AND r.occurred_at < e;
        GET DIAGNOSTICS n = ROW_COUNT;
        RAISE NOTICE '% a %: % eventos', s, e, n;
        COMMIT;
        s := e;
    END LOOP;
END;
$$;
REVOKE ALL ON PROCEDURE soc.republish_events(text, timestamptz, timestamptz, interval) FROM PUBLIC;

-- Uso: SELECT soc.republish_objects('incident');  (ou 'alert')
CREATE FUNCTION soc.republish_objects(p_kind text)
RETURNS bigint
LANGUAGE sql
SET search_path = pg_catalog, soc
AS $$
    WITH cur AS (
        INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
        SELECT o.kind, o.kind, o.id, o.last_update_at, o.payload
        FROM soc.security_object o
        WHERE o.kind = p_kind
        RETURNING 1
    ), ver AS (
        INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
        SELECT v.kind || '_version', v.kind, v.id || ':' || v.payload_hash, v.last_update_at, v.payload
        FROM soc.security_object_version v
        WHERE v.kind = p_kind
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM cur) + (SELECT count(*) FROM ver);
$$;
REVOKE ALL ON FUNCTION soc.republish_objects(text) FROM PUBLIC;
