import { describe, expect, it } from 'vitest';
import { backoffMs, parseRetryAfter } from '../src/graph/client.js';
import { canonicalJson, hashPayload, parseTimestamp, Semaphore } from '../src/util.js';

describe('canonicalJson', () => {
  it('ignora a ordem das chaves', () => {
    expect(canonicalJson({ b: 1, a: { d: [1, { y: 2, x: 1 }], c: null } })).toBe(
      canonicalJson({ a: { c: null, d: [1, { x: 1, y: 2 }] }, b: 1 }),
    );
  });

  it('diferencia conteúdos diferentes', () => {
    expect(hashPayload({ status: 'active' })).not.toBe(hashPayload({ status: 'resolved' }));
  });

  it('omite chaves undefined como o JSON.stringify', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});

describe('parseTimestamp', () => {
  it('aceita 7 casas decimais do Defender', () => {
    expect(parseTimestamp('2026-10-20T10:15:30.1234567Z').toISOString()).toBe('2026-10-20T10:15:30.123Z');
  });

  it('aceita horário sem fração e com deslocamento', () => {
    expect(parseTimestamp('2026-10-20T10:15:30-03:00').toISOString()).toBe('2026-10-20T13:15:30.000Z');
  });

  it('rejeita valores inválidos', () => {
    expect(() => parseTimestamp('20/10/2026')).toThrow();
    expect(() => parseTimestamp(null)).toThrow();
  });
});

describe('parseRetryAfter', () => {
  it('interpreta segundos', () => {
    expect(parseRetryAfter('7')).toBe(7000);
  });

  it('interpreta data HTTP', () => {
    const now = Date.parse('2026-10-20T10:00:00Z');
    expect(parseRetryAfter('Tue, 20 Oct 2026 10:00:30 GMT', now)).toBe(30_000);
  });

  it('ignora valores ausentes ou inválidos', () => {
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('amanhã')).toBeUndefined();
  });
});

describe('backoffMs', () => {
  it('cresce exponencialmente até o teto', () => {
    expect(backoffMs(0, 2000, 60_000, () => 0.999)).toBe(1998);
    expect(backoffMs(10, 2000, 60_000, () => 0.999)).toBe(59_940);
  });
});

describe('Semaphore', () => {
  it('respeita o limite de concorrência', async () => {
    const sem = new Semaphore(2);
    let active = 0;
    let peak = 0;
    const task = () =>
      sem.run(async () => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 5));
        active--;
      });
    await Promise.all(Array.from({ length: 8 }, task));
    expect(peak).toBe(2);
    expect(active).toBe(0);
  });
});
