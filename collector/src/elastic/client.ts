import { Agent, request } from 'node:https';

export interface ElasticConfig {
  url: string;
  user: string;
  password: string;
  ca?: string;
  requestTimeoutMs: number;
}

export interface ElasticSearcher {
  search(index: string, body: unknown): Promise<Record<string, unknown>>;
}

/** Cliente mínimo de leitura (_search) com usuário próprio e a CA do cluster. */
export class ElasticClient implements ElasticSearcher {
  private readonly agent: Agent;
  private readonly auth: string;

  constructor(private readonly cfg: ElasticConfig) {
    // Agente explícito: não passa pelo proxy corporativo de HTTPS_PROXY.
    this.agent = new Agent({ keepAlive: true, maxSockets: 2, ...(cfg.ca ? { ca: cfg.ca } : {}) });
    this.auth = `Basic ${Buffer.from(`${cfg.user}:${cfg.password}`).toString('base64')}`;
  }

  search(index: string, body: unknown): Promise<Record<string, unknown>> {
    const url = new URL(`/${encodeURIComponent(index)}/_search`, this.cfg.url);
    const payload = JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = request(url, {
        method: 'POST', agent: this.agent, timeout: this.cfg.requestTimeoutMs,
        headers: { authorization: this.auth, 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if ((res.statusCode ?? 0) >= 300) {
            // Só o tipo do erro: a resposta pode citar a consulta, nunca credenciais.
            const type = /"type"\s*:\s*"([^"]+)"/.exec(text)?.[1] ?? 'erro';
            reject(new Error(`Elasticsearch ${res.statusCode} em ${index}/_search: ${type}`));
            return;
          }
          try {
            resolve(JSON.parse(text) as Record<string, unknown>);
          } catch {
            reject(new Error(`Elasticsearch: resposta inválida de ${index}/_search`));
          }
        });
      });
      req.on('timeout', () => req.destroy(new Error(`Elasticsearch: tempo esgotado em ${index}/_search`)));
      req.on('error', reject);
      req.end(payload);
    });
  }
}
