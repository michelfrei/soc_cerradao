/** Mesmo predicado das consultas KQL: contains/!contains não diferenciam caixa. */
export function isServerInScope(name: string): boolean {
  const n = name.toLowerCase();
  return (n.includes('srv') || n.includes('fisico')) && !n.includes('note') && !n.includes('micro');
}
