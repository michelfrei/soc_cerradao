import { ConfidentialClientApplication, type Configuration } from '@azure/msal-node';
import type { Config } from '../config.js';

const SCOPE = 'https://graph.microsoft.com/.default';

export interface TokenProvider {
  getToken(forceRefresh?: boolean): Promise<string>;
}

/** Client credentials (segredo ou certificado). O MSAL mantém o token em cache. */
export class GraphAuth implements TokenProvider {
  private readonly app: ConfidentialClientApplication;

  constructor(cfg: Config['graph']) {
    const auth: Configuration['auth'] = {
      clientId: cfg.clientId,
      authority: `${cfg.authorityHost}/${cfg.tenantId}`,
    };
    if (cfg.credential.kind === 'secret') {
      auth.clientSecret = cfg.credential.clientSecret;
    } else {
      auth.clientCertificate = {
        thumbprintSha256: cfg.credential.thumbprintSha256,
        privateKey: cfg.credential.privateKey,
      };
    }
    this.app = new ConfidentialClientApplication({ auth });
  }

  async getToken(forceRefresh = false): Promise<string> {
    const result = await this.app.acquireTokenByClientCredential({
      scopes: [SCOPE],
      skipCache: forceRefresh,
    });
    if (!result?.accessToken) throw new Error('o Entra ID não retornou token de acesso');
    return result.accessToken;
  }
}
