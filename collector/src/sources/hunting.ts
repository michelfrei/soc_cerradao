import type { HuntingSourceConfig } from '../config.js';
import { ensurePartitions, getCheckpoint, insertEvents, setCheckpoint, withTransaction, type EventRow, type Pool, type RunCounters } from '../db.js';
import { GraphError, type GraphClient } from '../graph/client.js';
import type { Logger } from '../logger.js';
import { addHours, addMinutes, isoUtc, parseTimestamp, sha256 } from '../util.js';

export interface HuntingWindow {
  /** Início lógico da janela (checkpoint anterior). */
  start: Date;
  /** Fim exclusivo; vira o próximo checkpoint. */
  end: Date;
  /** Início efetivo da consulta, recuado pela sobreposição. */
  queryStart: Date;
}

type WindowSettings = Pick<HuntingSourceConfig, 'initialLookbackHours' | 'ingestionLagMinutes' | 'maxWindowMinutes' | 'overlapMinutes'>;

/** Próxima janela a consultar, ou null se a coleta já alcançou o presente. */
export function nextWindow(checkpoint: Date | null, now: Date, s: WindowSettings): HuntingWindow | null {
  const start = checkpoint ?? addHours(now, -s.initialLookbackHours);
  const limit = addMinutes(now, -s.ingestionLagMinutes);
  const maxEnd = addMinutes(start, s.maxWindowMinutes);
  const end = maxEnd < limit ? maxEnd : limit;
  if (end.getTime() - start.getTime() < 60_000) return null;
  return { start, end, queryStart: addMinutes(start, -s.overlapMinutes) };
}

export function renderQuery(template: string, from: Date, to: Date): string {
  return template.replaceAll('{{start}}', isoUtc(from)).replaceAll('{{end}}', isoUtc(to));
}

/**
 * Chave determinística do evento. ReportId é único por dispositivo; combinado
 * com horário e ação identifica a linha. Sem esses campos, usa o conteúdo.
 */
export function eventKey(table: string, row: Record<string, unknown>): string {
  const { DeviceId, ReportId, Timestamp, ActionType } = row;
  if (DeviceId != null && ReportId != null && Timestamp != null) {
    return sha256(`${table}|${String(DeviceId)}|${String(ReportId)}|${String(Timestamp)}|${String(ActionType ?? '')}`);
  }
  return sha256(`${table}|${JSON.stringify(row)}`);
}

export function toEventRow(table: string, row: Record<string, unknown>): EventRow {
  const ts = row.Timestamp;
  parseTimestamp(ts); // valida antes de gravar
  const str = (v: unknown): string | null => (v == null || v === '' ? null : String(v));
  return {
    key: eventKey(table, row),
    ts: ts as string,
    device_id: str(row.DeviceId),
    device_name: str(row.DeviceName),
    action_type: str(row.ActionType),
    payload: row,
  };
}

class WindowTooLarge extends Error {}

function isLimitError(err: unknown): boolean {
  if (!(err instanceof GraphError)) return false;
  if (err.status !== 400) return false;
  return /(limit|exceed|too (large|many)|timeout|timed out)/i.test(err.message);
}

export async function collectHunting(
  src: HuntingSourceConfig,
  deps: { pool: Pool; graph: GraphClient; log: Logger },
  counters: RunCounters,
): Promise<void> {
  const { pool, graph, log } = deps;

  const fetchRange = async (from: Date, to: Date): Promise<Record<string, unknown>[]> => {
    const minutes = (to.getTime() - from.getTime()) / 60_000;
    let rows: Record<string, unknown>[] | undefined;
    try {
      const res = (await graph.request('POST', '/security/runHuntingQuery', counters, {
        Query: renderQuery(src.query, from, to),
      })) as { results?: unknown };
      if (!Array.isArray(res.results)) throw new Error('resposta do runHuntingQuery sem "results"');
      rows = res.results as Record<string, unknown>[];
      if (rows.length < src.maxRows) return rows;
    } catch (err) {
      if (!isLimitError(err)) throw err;
      log.warn({ source: src.name, minutes, err: (err as Error).message }, 'limite do Advanced Hunting; dividindo janela');
    }
    if (minutes / 2 < src.minWindowMinutes) {
      throw new WindowTooLarge(
        `${src.name}: janela de ${minutes} min ainda excede maxRows (${src.maxRows}) ou os limites da API; ` +
          'reduza a consulta ou ajuste minWindowMinutes/maxRows',
      );
    }
    log.info({ source: src.name, minutes, rows: rows?.length }, 'dividindo janela');
    const mid = new Date(from.getTime() + (to.getTime() - from.getTime()) / 2);
    const left = await fetchRange(from, mid);
    const right = await fetchRange(mid, to);
    return left.concat(right);
  };

  for (let i = 0; i < src.maxWindowsPerRun; i++) {
    const w = nextWindow(await getCheckpoint(pool, src.name), new Date(), src);
    if (!w) break;
    counters.windowStart ??= w.queryStart;
    counters.windowEnd = w.end;

    const raw = await fetchRange(w.queryStart, w.end);
    counters.fetched += raw.length;

    const rows: EventRow[] = [];
    for (const r of raw) {
      try {
        rows.push(toEventRow(src.table, r));
      } catch (err) {
        log.error({ source: src.name, err: (err as Error).message }, 'linha ignorada: formato inesperado');
      }
    }

    if (rows.length > 0) {
      let min = parseTimestamp(rows[0]!.ts);
      let max = min;
      for (const r of rows) {
        const t = parseTimestamp(r.ts);
        if (t < min) min = t;
        if (t > max) max = t;
      }
      // +1 s: o PostgreSQL arredonda para microssegundos (ex.: 23:59:59.9999999
      // vira 00:00:00 do mês seguinte) e a partição precisa existir.
      await ensurePartitions(pool, min, new Date(max.getTime() + 1000));
    }

    await withTransaction(pool, async (client) => {
      counters.inserted += await insertEvents(client, src.name, src.table, rows);
      await setCheckpoint(client, src.name, w.end);
    });
    log.debug({ source: src.name, from: w.queryStart, to: w.end, rows: rows.length }, 'janela gravada');
  }
}
