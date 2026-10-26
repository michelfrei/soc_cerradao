// Lista fechada de consultas ao FortiGate. Nada de texto livre: cada ferramenta
// corresponde a um comando fixo; o único parâmetro aceito é o id inteiro da política.

export const TOOLS = {
  status: {
    description: 'Estado geral do FortiGate (versão, modelo, HA, licenças).',
    command: () => 'get system status',
  },
  interfaces_status: {
    description: 'Interfaces físicas: estado do link, velocidade e endereço.',
    command: () => 'get system interface physical',
  },
  interfaces_config: {
    description: 'Configuração das interfaces (show system interface), com segredos removidos.',
    command: () => 'show system interface',
  },
  routes: {
    description: 'Tabela de rotas ativa (get router info routing-table all).',
    command: () => 'get router info routing-table all',
  },
  policies: {
    description: 'Todas as políticas de firewall (show firewall policy).',
    command: () => 'show firewall policy',
  },
  policy: {
    description: 'Uma política de firewall pelo id (show firewall policy <id>).',
    params: { id: { type: 'integer', minimum: 0, maximum: 2147483647, description: 'policyid' } },
    command: ({ id }) => `show firewall policy ${id}`,
  },
};

/** Valida o pedido e devolve o comando exato, ou lança erro sem ecoar o texto recebido. */
export function resolveCommand(tool, args = {}) {
  if (typeof tool !== 'string' || !Object.hasOwn(TOOLS, tool)) throw new Error('ferramenta não permitida');
  const spec = TOOLS[tool];
  const allowed = Object.keys(spec.params ?? {});
  for (const key of Object.keys(args ?? {})) if (!allowed.includes(key)) throw new Error(`parâmetro não permitido: ${key.slice(0, 32)}`);
  for (const [key, p] of Object.entries(spec.params ?? {})) {
    const v = args[key];
    if (!Number.isInteger(v) || v < p.minimum || v > p.maximum) throw new Error(`${key} precisa ser inteiro entre ${p.minimum} e ${p.maximum}`);
  }
  return spec.command(args);
}

const SET_LINE = /^(\s*set\s+)(\S+)(\s+).*$/i;
const ENC = /\bENC\s+\S+/g;
const PEM = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;

/** Atributos do FortiOS que guardam segredo (keylife, keepalive etc. não entram). */
export function isSecretAttribute(name) {
  const n = name.toLowerCase();
  return /password|passwd|secret|passphrase|token|private-key/.test(n) || /(^|-)(key|psk)\d*$/.test(n);
}

/** Remove senhas, chaves e valores cifrados (ENC ...) da saída do FortiGate. */
export function redact(text) {
  return text
    .replace(PEM, '<chave privada removida>')
    .split(/\r?\n/)
    .map((line) => {
      const m = SET_LINE.exec(line);
      if (m && isSecretAttribute(m[2])) return `${m[1]}${m[2]}${m[3]}<removido>`;
      return line.replace(ENC, 'ENC <removido>');
    })
    .join('\n');
}
