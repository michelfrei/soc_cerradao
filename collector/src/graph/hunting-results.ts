/**
 * Graph v1 documenta schema/results, sem contrato de estatísticas ou sucesso parcial.
 * Não toma HTTP 200 como suficiente se o envelope contiver erros, paginação ou
 * marcadores explícitos de resultado parcial/truncado (inclusive dentro de stats).
 * Isso não comprova completude de dados que o próprio serviço não reportou.
 */
export function completeHuntingResults(response: unknown, limit: number, source: string): unknown[] {
  if (response === null || typeof response !== 'object' || Array.isArray(response)) {
    throw new Error(`${source}: envelope Graph inválido`);
  }
  const envelope = response as Record<string, unknown>;
  if (!Array.isArray(envelope.results)) throw new Error(`${source}: Graph não retornou lista results`);
  const nonempty = (value: unknown): boolean => value !== undefined && value !== null && value !== false && value !== 0 && value !== '0' && value !== 'false' && value !== '' &&
    (!Array.isArray(value) || value.length > 0) && (typeof value !== 'object' || Object.keys(value).length > 0);
  const inspect = (metadata: Record<string, unknown>): void => {
    for (const [key, value] of Object.entries(metadata)) {
      const k = key.toLowerCase().replace(/[_-]/g, '');
      if ((/^(error|errors|partialerror|partialerrors|oneapierrors|failure|failures|partialqueryfailures)$/.test(k) && nonempty(value)) ||
          (/^(partial|ispartial|truncated|istruncated|isincomplete|haserrors|haspartialresults|partialresults|haspartialfailures)$/.test(k) && nonempty(value)) ||
          (/^(complete|iscomplete)$/.test(k) && (value === false || value === 'false')) ||
          (/^(status|querystatus|resultstatus)$/.test(k) && typeof value === 'string' && /partial|truncat|fail|error/i.test(value)) ||
          (k.endsWith('nextlink') && nonempty(value))) {
        throw new Error(`${source}: Graph sinalizou erro/resultado parcial (${key}); snapshot recusado`);
      }
      if (value && typeof value === 'object' && !Array.isArray(value)) inspect(value as Record<string, unknown>);
      if (Array.isArray(value)) for (const item of value) if (item && typeof item === 'object') inspect(item as Record<string, unknown>);
    }
  };
  inspect(Object.fromEntries(Object.entries(envelope).filter(([key]) => !['results', 'schema'].includes(key))));
  if (envelope.results.length >= limit) throw new Error(`${source}: limite ${limit} atingido; snapshot incompleto recusado`);
  return envelope.results;
}
