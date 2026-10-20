import { pino, type Logger } from 'pino';

export type { Logger };

export function createLogger(level: string): Logger {
  return pino({
    level,
    base: { service: 'soc-collector' },
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: ['password', '*.password', 'secret', '*.secret', 'clientSecret', '*.clientSecret', 'authorization', '*.authorization', 'headers.authorization', 'privateKey', '*.privateKey'],
      censor: '[removido]',
    },
  });
}
