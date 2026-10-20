SELECT id,
       txid::text::bigint AS txid,
       entity,
       dataset,
       doc_id,
       to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at_iso,
       payload::text AS payload_json
FROM soc.publication
WHERE txid > (:sql_last_value)::text::xid8
  AND txid < pg_snapshot_xmin(pg_current_snapshot())
ORDER BY txid, id
