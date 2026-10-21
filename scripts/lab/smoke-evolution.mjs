// Integração local descartável. Não inicia o coletor nem chama Graph/VMs reais.
// node scripts/lab/smoke-evolution.mjs [--keep]
// node scripts/lab/smoke-evolution.mjs --cleanup <diretório retornado por --keep>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { checkAccess } from './check-access.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function docker(args, { input, quiet = false, allowFailure = false } = {}) {
  const result = spawnSync('docker', args, { encoding:'utf8', input, env:process.env, maxBuffer:12*1024*1024 });
  if (result.status !== 0 && !allowFailure) throw new Error(`Docker ${args[0]} falhou: ${result.stderr || result.stdout || result.error}`);
  if (!quiet && result.stdout.trim()) console.log(result.stdout.trim());
  if (!quiet && result.stderr.trim()) console.log(result.stderr.trim());
  return result;
}
function safeSession(dir) {
  const absolute = path.resolve(dir);
  if (path.dirname(absolute) !== path.resolve(os.tmpdir()) || !path.basename(absolute).startsWith('soc-evolution-')) throw new Error('Diretório de sessão fora do TEMP esperado');
  const manifest = JSON.parse(fs.readFileSync(path.join(absolute,'session.json'),'utf8'));
  if (!/^soc-evolution-[a-f0-9]{8}$/.test(manifest.project)) throw new Error('Projeto de laboratório inválido');
  return { absolute, manifest };
}
function cleanup(dir) {
  const {absolute,manifest:m}=safeSession(dir);
  Object.assign(process.env,{STACK_VERSION:'9.5.5',SOC_PG_HOST:'postgres',SOC_LOGSTASH_DB_PASSWORD:m.password,
    ELASTIC_PASSWORD:m.password,KIBANA_PASSWORD:m.password,SOC_ES_LOGSTASH_PASSWORD:m.password,
    KIBANA_PUBLIC_URL:m.kibana,KIBANA_ENCRYPTION_KEY:'0'.repeat(64),KIBANA_SECURITY_KEY:'1'.repeat(64),
    KIBANA_REPORTING_KEY:'2'.repeat(64),GRAPH_TENANT_ID:'00000000-0000-0000-0000-000000000000',
    GRAPH_CLIENT_ID:'00000000-0000-0000-0000-000000000000'});
  docker(['compose','--project-name',m.project,'--env-file',path.join(root,'docker/.env.example'),'-f',path.join(root,'docker/compose.yml'),'-f',path.join(absolute,'override.yml'),'down','--volumes','--remove-orphans'],{quiet:true,allowFailure:true});
  docker(['rm','-f',`${m.project}-pg`],{quiet:true,allowFailure:true});
  docker(['volume','rm',`${m.project}_pgdata`,`${m.project}_pgtls`],{quiet:true,allowFailure:true});
  docker(['image','rm',`${m.project}/logstash:9.5.5`],{quiet:true,allowFailure:true});
  docker(['network','rm',m.project],{quiet:true,allowFailure:true});
  fs.rmSync(absolute,{recursive:true,force:true});
  console.log('Laboratório descartável removido.');
}
if(process.argv.includes('--cleanup')) {
  cleanup(process.argv[process.argv.indexOf('--cleanup')+1]);
  process.exit(0);
}
const project=`soc-evolution-${randomBytes(4).toString('hex')}`;
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'soc-evolution-'));
const password=randomBytes(24).toString('hex');
const manifest={project,password,root,dir,kibana:'https://localhost:15601',es:'https://localhost:19200'};
fs.writeFileSync(path.join(dir,'session.json'),JSON.stringify(manifest));
Object.assign(process.env,{
  STACK_VERSION:'9.5.5',SOC_PG_HOST:'postgres',SOC_PG_PORT:'5432',SOC_PG_SSLMODE:'verify-full',
  SOC_LOGSTASH_DB_PASSWORD:password,ELASTIC_PASSWORD:password,KIBANA_PASSWORD:password,
  SOC_ES_LOGSTASH_PASSWORD:password,SOC_ES_LOGSTASH_USER:'soc_logstash',
  KIBANA_PUBLIC_URL:manifest.kibana,KIBANA_ENCRYPTION_KEY:randomBytes(32).toString('hex'),
  KIBANA_SECURITY_KEY:randomBytes(32).toString('hex'),KIBANA_REPORTING_KEY:randomBytes(32).toString('hex'),
  GRAPH_TENANT_ID:'00000000-0000-0000-0000-000000000000',GRAPH_CLIENT_ID:'00000000-0000-0000-0000-000000000000',
  ES_HEAP:'1g',ES_MEM_LIMIT:'3g',LS_HEAP:'512m',LS_MEM_LIMIT:'1500m',KIBANA_MEM_LIMIT:'2g'
});
fs.writeFileSync(path.join(dir,'override.yml'),`services:
  es01:
    volumes: !override
      - certs_public:/usr/share/elasticsearch/config/certs/ca:ro
      - certs_es:/usr/share/elasticsearch/config/certs/es01:ro
      - smoke_esdata:/usr/share/elasticsearch/data
      - smoke_snapshots:/usr/share/elasticsearch/snapshots
    ports: !override
      - "127.0.0.1:19200:9200"
  kibana:
    ports: !override
      - "127.0.0.1:15601:5601"
  logstash:
    image: ${project}/logstash:9.5.5
    volumes: !override
      - certs_public:/usr/share/logstash/certs/ca:ro
      - certs_public:/usr/share/logstash/pg-ca:ro
      - ${root.replaceAll('\\','/')}/logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - ${root.replaceAll('\\','/')}/logstash/config/pipelines.yml:/usr/share/logstash/config/pipelines.yml:ro
      - ${root.replaceAll('\\','/')}/logstash/config/identities.json:/usr/share/logstash/config/identities.json:ro
      - ${root.replaceAll('\\','/')}/logstash/pipeline:/usr/share/logstash/pipeline:ro
      - ${root.replaceAll('\\','/')}/logstash/sql:/usr/share/logstash/sql:ro
      - smoke_lsdata:/usr/share/logstash/data
volumes:
  smoke_esdata: {}
  smoke_snapshots: {}
  smoke_lsdata: {}
networks:
  default:
    name: ${project}
    external: true
`);
const composeArgs=['compose','--project-name',project,'--env-file',path.join(root,'docker/.env.example'),'-f',path.join(root,'docker/compose.yml'),'-f',path.join(dir,'override.yml')];
const compose=(args,opts)=>docker([...composeArgs,...args],opts);
const pg=`${project}-pg`;
const sql=(text)=>docker(['exec','-i',pg,'psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-d','soc','-f','-'],{input:text,quiet:true});
const es=(method,endpoint,body)=>{
  const args=['exec','-i',`${project}-es01-1`,'curl','-sS','--fail-with-body','--cacert','config/certs/ca/ca.crt','-K-','-X',method,`https://localhost:9200${endpoint}`,'-H','Content-Type: application/json'];
  // Credenciais pelo stdin; corpo, quando necessário, usa argumento de dados sem segredos.
  if(body)args.push('--data-binary',JSON.stringify(body));
  const result=docker(args,{input:`user = "elastic:${password}"\n`,quiet:true});
  return JSON.parse(result.stdout);
};
let success=false;
try {
  console.log(`Sessão local: ${dir}`);
  docker(['network','create',project],{quiet:true});
  console.log('Gerando certificados isolados e iniciando Elasticsearch 9.5.5.');
  compose(['run','--rm','certs']);
  docker(['run','--rm','--user','0','-v',`${project}_ca_private:/ca:ro`,'-v',`${project}_pgtls:/tls`,'--entrypoint','bash','postgres:18','-ec',
    'openssl req -newkey rsa:2048 -nodes -keyout /tls/server.key -out /tmp/pg.csr -subj /CN=postgres -addext subjectAltName=DNS:postgres >/dev/null 2>&1; openssl x509 -req -in /tmp/pg.csr -CA /ca/ca/ca.crt -CAkey /ca/ca/ca.key -set_serial 123 -days 2 -copy_extensions copy -out /tls/server.crt >/dev/null 2>&1; chown 999:999 /tls/server.key /tls/server.crt; chmod 600 /tls/server.key; chmod 644 /tls/server.crt'],{quiet:true});
  docker(['run','-d','--name',pg,'--network',project,'--network-alias','postgres','--memory','512m','-e',`POSTGRES_PASSWORD=${password}`,'-v',`${project}_pgdata:/var/lib/postgresql`,'-v',`${project}_pgtls:/tls:ro`,'postgres:18','-c','ssl=on','-c','ssl_cert_file=/tls/server.crt','-c','ssl_key_file=/tls/server.key'],{quiet:true});
  for(let i=0;i<60;i++) {
    if(docker(['exec',pg,'pg_isready','-U','postgres','-q'],{quiet:true,allowFailure:true}).status===0)break;
    await sleep(1000);
  }
  docker(['exec','-i','-e',`SOC_COLLECTOR_PASSWORD=${password}`,'-e',`SOC_LOGSTASH_PASSWORD=${password}`,pg,'psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres','-f','-'],{input:fs.readFileSync(path.join(root,'postgres/bootstrap.sql'),'utf8'),quiet:true});
  for(const file of fs.readdirSync(path.join(root,'postgres/migrations')).filter(f=>f.endsWith('.sql')).sort()) {
    sql(`BEGIN; SET ROLE soc_owner;\n${fs.readFileSync(path.join(root,'postgres/migrations',file),'utf8')}\nINSERT INTO soc.schema_migrations(version) VALUES ('${file.slice(0,-4)}'); COMMIT;`);
  }
  sql(fs.readFileSync(path.join(root,'scripts/lab/dados-sinteticos.sql'),'utf8'));
  sql(fs.readFileSync(path.join(root,'scripts/lab/cenarios-deteccao.sql'),'utf8'));
  sql(fs.readFileSync(path.join(root,'scripts/lab/evolution-smoke.sql'),'utf8'));
  compose(['up','-d','--wait','--wait-timeout','240','es01']);
  compose(['run','--rm','setup']);
  console.log('Construindo Logstash e iniciando Kibana; sem coletor/Graph.');
  compose(['build','logstash'],{quiet:true});
  compose(['up','-d','--wait','--wait-timeout','300','kibana','logstash']);
  compose(['run','--rm','kibana-setup']);
  checkAccess(dir);
  console.log('Aguardando documentos, inventário e métricas via PostgreSQL TLS verify-full.');
  let metrics;
  for(let i=0;i<60;i++) {
    try {
      metrics=es('GET','/soc-metrics-*/_count');
      const devices=es('GET','/soc-devices/_count');
      if(metrics.count>0&&devices.count===2)break;
    } catch {}
    await sleep(3000);
  }
  const scoped=es('POST','/soc-events-*/_count',{query:{terms:{'host.name':['srv-note-excluded','fisico-micro-excluded']}}});
  if(scoped.count!==0)throw new Error('Máquinas excluídas chegaram ao índice');
  const inventory=es('GET','/soc-devices/_count');
  if(inventory.count!==2)throw new Error('Inventário sintético incompleto');
  const oldIncident=es('GET','/soc-incidents/_doc/smoke-old-active');
  if(!oldIncident.found||oldIncident._source.soc.object.status!=='active')throw new Error('Estado antigo ativo ausente');
  const identities=es('POST','/soc-events-*/_search',{size:0,query:{prefix:{'host.id':'smoke-host-'}},aggs:{identities:{terms:{field:'soc.identity.correlation_key',size:20}}}});
  if(identities.aggregations.identities.buckets.length!==4)throw new Error('Contas de domínios/hosts distintos foram misturadas ou eventos ausentes');
  const datasets=es('POST','/soc-metrics-*/_search',{size:0,aggs:{datasets:{terms:{field:'event.dataset'}}}}).aggregations.datasets.buckets.map(b=>b.key);
  for(const required of ['soc.database_capacity','soc.elasticsearch_capacity'])if(!datasets.includes(required))throw new Error(`Métrica ausente: ${required}`);
  console.log('APROVADO: importação Kibana, migrações, ingestão TLS, identidades, exclusões e capacidade PG/ES.');
  fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify({status:'passed',datasets,identities:4,excluded:scoped.count}));
  success=true;
} finally {
  if(process.argv.includes('--keep')) {
    console.log(`Laboratório mantido para inspeção local: ${dir}`);
    console.log(`Após inspeção: node scripts/lab/smoke-evolution.mjs --cleanup "${dir}"`);
  } else {
    cleanup(dir);
  }
  if(!success)console.log('Smoke não concluído; verifique o erro anterior.');
}
