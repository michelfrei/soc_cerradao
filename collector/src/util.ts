import { createHash } from 'node:crypto';

/** JSON com chaves ordenadas: o mesmo conteúdo gera sempre o mesmo texto. */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const parts = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return `{${parts.join(',')}}`;
}

export function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

export function hashPayload(value: unknown): string {
  return sha256(canonicalJson(value));
}

/**
 * Converte horários do Defender (até 7 casas decimais) em Date.
 * Mantém milissegundos; a precisão original segue no payload.
 */
export function parseTimestamp(value: unknown): Date {
  if (typeof value !== 'string') throw new Error(`horário inválido: ${String(value)}`);
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!m) throw new Error(`horário inválido: ${value}`);
  const frac = m[2] ? m[2].slice(0, 4).padEnd(4, '0') : '';
  const d = new Date(`${m[1]}${frac}${m[3]}`);
  if (Number.isNaN(d.getTime())) throw new Error(`horário inválido: ${value}`);
  return d;
}

/** Formato aceito pelo KQL em datetime(...) e pelo OData em $filter. */
export function isoUtc(d: Date): string {
  return d.toISOString();
}

export function addMinutes(d: Date, minutes: number): Date {
  return new Date(d.getTime() + minutes * 60_000);
}

export function addHours(d: Date, hours: number): Date {
  return addMinutes(d, hours * 60);
}

/** Limita quantas operações rodam ao mesmo tempo. */
export class Semaphore {
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(private readonly max: number) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) {
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    } else {
      this.active++;
    }
    try {
      return await fn();
    } finally {
      const next = this.waiting.shift();
      if (next) next();
      else this.active--;
    }
  }
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
