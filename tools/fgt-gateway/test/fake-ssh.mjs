// SSH falso para os testes: ecoa o comando e devolve uma saída com segredo para conferir a remoção.
const args = process.argv.slice(2);
process.stdout.write(`ARGS ${args.at(-1)}\n`);
process.stdout.write('config vpn ipsec phase1-interface\n    edit "vpn1"\n        set psksecret ENC SegredoFalso==\n    next\nend\n');
