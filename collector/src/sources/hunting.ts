import type { HuntingSourceConfig } from '../config.js';
import { ensurePartitions, getCheckpoint, insertEvents, setCheckpoint, withTransaction, type EventRow, type Pool, type RunCounters } from '../db.js';
import { GraphError, type GraphClient } from '../graph/client.js';
import type { Logger } from '../logger.js';
import { addHours, addMinutes, isoUtc, parseTimestamp, sha256 } from '../util.js';
import { isServerInScope } from '../scope.js';

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

  /** Converte, garante as partições e grava; o checkpoint, se houver, vai na mesma transação. */
  const store = async (raw: Record<string, unknown>[], checkpoint: Date | undefined): Promise<void> => {
    const rows: EventRow[] = [];
    for (const r of raw) {
      // Defesa local: as fontes de processo/rede seguem o mesmo escopo do KQL.
      // Não há allowlist do catálogo esperado. Exclusões de nomes prevalecem.
      if ((src.table === 'DeviceProcessEvents' || src.table === 'DeviceNetworkEvents') &&
          !isServerInScope(typeof r.DeviceName === 'string' ? r.DeviceName : '')) continue;
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
      if (checkpoint) await setCheckpoint(client, src.name, checkpoint);
    });
  };

  /**
   * Consulta [from, to) e grava. Se o resultado atingir maxRows (ou a API recusar
   * pelo limite), divide ao meio e grava cada metade assim que ela chega, sem
   * acumular a janela inteira em memória. O checkpoint segue para a última
   * metade, então só avança depois que todas as partes foram gravadas.
   */
  const processRange = async (from: Date, to: Date, checkpoint: Date | undefined): Promise<void> => {
    const minutes = (to.getTime() - from.getTime()) / 60_000;
    let returned: number | undefined;
    try {
      const res = (await graph.request('POST', '/security/runHuntingQuery', counters, {
        Query: renderQuery(src.query, from, to),
      })) as { results?: unknown };
      if (!Array.isArray(res.results)) throw new Error('resposta do runHuntingQuery sem "results"');
      const rows = res.results as Record<string, unknown>[];
      if (rows.length < src.maxRows) {
        counters.fetched += rows.length;
        await store(rows, checkpoint);
        return;
      }
      returned = rows.length;
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
    log.info({ source: src.name, minutes, rows: returned }, 'dividindo janela');
    const mid = new Date(from.getTime() + (to.getTime() - from.getTime()) / 2);
    await processRange(from, mid, undefined);
    await processRange(mid, to, checkpoint);
  };

  for (let i = 0; i < src.maxWindowsPerRun; i++) {
    const w = nextWindow(await getCheckpoint(pool, src.name), new Date(), src);
    if (!w) break;
    counters.windowStart ??= w.queryStart;
    counters.windowEnd = w.end;
    await processRange(w.queryStart, w.end, w.end);
    log.debug({ source: src.name, from: w.queryStart, to: w.end }, 'janela gravada');
  }
}
