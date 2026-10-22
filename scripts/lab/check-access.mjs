// Somente a sessão descartável gerada por smoke-evolution.mjs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export function checkAccess(dir) {
  const absolute=path.resolve(dir);
  if(path.dirname(absolute)!==path.resolve(os.tmpdir())||!path.basename(absolute).startsWith('soc-evolution-'))throw new Error('Sessão fora do TEMP esperado');
  const m=JSON.parse(fs.readFileSync(path.join(absolute,'session.json'),'utf8'));
  if(!/^soc-evolution-[a-f0-9]{8}$/.test(m.project))throw new Error('Projeto de teste inválido');
  function request(service,method,endpoint,body,user='elastic') {
    const url=service==='es'?`https://localhost:9200${endpoint}`:`https://kibana:5601/s/soc${endpoint}`;
    const args=['exec','-i',`${m.project}-es01-1`,'curl','-sS','--cacert','config/certs/ca/ca.crt','-K-','-X',method,url,'-H','Content-Type: application/json','-H','kbn-xsrf: smoke-test','-H','elastic-api-version: 2023-10-31','-w','\n%{http_code}'];
    if(body)args.push('--data-binary',JSON.stringify(body));
    const r=spawnSync('docker',args,{encoding:'utf8',input:`user = "${user}:${m.password}"\n`,maxBuffer:8*1024*1024});
    if(r.status!==0)throw new Error(`Requisição local falhou: ${r.stderr}`);
    const split=r.stdout.lastIndexOf('\n');
    const raw=r.stdout.slice(0,split);
    let data;try{data=JSON.parse(raw);}catch{data=raw;}
    return {status:Number(r.stdout.slice(split+1)),data};
  }
  function expect(response,status,label) {
    if(![].concat(status).includes(response.status))throw new Error(`${label}: status ${response.status}: ${JSON.stringify(response.data).slice(0,600)}`);
    console.log(`APROVADO: ${label}`);
    return response.data;
  }
  for(const [user,role]of [['smoke-observer','soc_observer'],['smoke-analyst','soc_analyst'],['smoke-admin','soc_admin']]) {
    expect(request('es','PUT',`/_security/user/${user}`,{password:m.password,roles:[role]}),200,`usuário temporário ${role}`);
    const privileges=expect(request('es','POST','/_security/user/_has_privileges',{
      cluster:['manage_security'],index:[{names:['soc-events-*'],privileges:['read','write','delete_index']},{names:['soc-posture'],privileges:['read','write','delete_index']},{names:['.alerts-security.alerts-soc'],privileges:['read']}]
    },user),200,`privilégios efetivos ${role}`);
    if(privileges.cluster.manage_security||!privileges.index['soc-events-*'].read||privileges.index['soc-events-*'].write||privileges.index['soc-events-*'].delete_index||!privileges.index['.alerts-security.alerts-soc'].read||!privileges.index['soc-posture'].read||privileges.index['soc-posture'].write||privileges.index['soc-posture'].delete_index)throw new Error(`Permissões incorretas em ${role}`);
    const dashboards=expect(request('kb','GET','/api/saved_objects/_find?type=dashboard&per_page=100',undefined,user),200,`${role} consulta dashboards SOC`);
    if(dashboards.saved_objects.length!==8)throw new Error('Quantidade inesperada de dashboards');
  }
  expect(request('kb','GET','/api/detection_engine/rules/_find',undefined,'smoke-observer'),403,'observer não gerencia detecções');
  const rules=expect(request('kb','GET','/api/detection_engine/rules/_find?per_page=100',undefined,'smoke-analyst'),200,'analyst consulta regras');
  if(rules.data.length!==8)throw new Error('Esperadas oito regras');
  expect(request('kb','PATCH','/api/detection_engine/rules',{id:rules.data[0].id,name:'Teste proibido de alteração'},'smoke-analyst'),403,'analyst não altera regras');
  expect(request('kb','POST','/api/cases',{title:'Caso sintético de validação',description:'Somente laboratório descartável',tags:['smoke'],connector:{id:'none',name:'none',type:'.none',fields:null},settings:{syncAlerts:true},owner:'securitySolution'},'smoke-analyst'),[200,201],'analyst cria Case SOC');
  // Atualiza a autorização das regras com o papel funcional, sem superuser.
  expect(request('kb','PATCH','/api/detection_engine/rules',{id:rules.data[0].id,name:rules.data[0].name},'smoke-admin'),200,'admin edita regra SOC sem superuser');
  expect(request('kb','GET','/api/security/role/superuser',undefined,'smoke-admin'),403,'admin SOC não administra segurança do cluster');
  console.log('APROVADO: perfis observer/analyst/admin funcionais e sem escrita em eventos.');
}
if(process.argv[1]&&path.resolve(process.argv[1])===path.resolve(fileURLToPath(import.meta.url)))checkAccess(process.argv[2]);
