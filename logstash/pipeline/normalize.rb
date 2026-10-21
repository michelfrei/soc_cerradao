# Normalização compartilhada por eventos, inventário e métricas do piloto.
# Executado pelo filtro ruby; os testes abaixo rodam com --config.test_and_exit.
require 'json'
require 'time'

def register(params)
  path = params.fetch('identities_path', '/usr/share/logstash/config/identities.json')
  config = JSON.parse(File.read(path))
  @accounts = config.fetch('accounts')
  raise 'identities.json: accounts precisa ser uma lista' unless @accounts.is_a?(Array)
  @accounts.each do |account|
    unless account.is_a?(Hash) && %w[person service machine system unknown].include?(account['type'])
      raise 'identities.json: cada conta precisa de type válido'
    end
    unless present(account['sid']) || (present(account['name']) && (present(account['domain']) || present(account['host_id'])))
      raise 'identities.json: especifique sid ou name com domain/host_id'
    end
    unless account['privileged'].nil? || [true, false].include?(account['privileged'])
      raise 'identities.json: privileged precisa ser booleano'
    end
  end
end

def present(value)
  return nil if value.nil?
  text = value.to_s.strip
  text.empty? || text == '-' ? nil : text
end

def normalized(value)
  text = present(value)
  text && text.downcase
end

def in_scope(name)
  text = normalized(name).to_s
  (text.include?('srv') || text.include?('fisico')) && !text.include?('note') && !text.include?('micro')
end

def boolean(value)
  return value if value == true || value == false
  return true if value.to_s.downcase == 'true'
  return false if value.to_s.downcase == 'false'
  nil
end

def identity(event, data)
  name = normalized(data['AccountName'])
  domain = normalized(data['AccountDomain'])
  if name && name.include?('\\')
    embedded_domain, name = name.split('\\', 2)
    domain ||= embedded_domain
  end
  sid = normalized(data['AccountSid'])
  sid = nil unless sid && sid.match?(/\As-\d+(?:-\d+)+\z/) && sid != 's-1-0-0'
  return unless name || sid

  host_name = normalized(data['DeviceName'])
  host_id = normalized(data['DeviceId']) || host_name
  short_name = host_name && host_name.split('.').first
  system_domain = ['nt authority', 'nt service', 'iis apppool', 'builtin', 'window manager', 'font driver host'].include?(domain)
  well_known_sid = sid && !sid.start_with?('s-1-5-21-') && !sid.start_with?('s-1-12-1-')
  local = well_known_sid || (domain && (['.', 'localhost', 'workgroup', short_name, host_name].compact.include?(domain) || system_domain))
  scope = local ? 'local' : domain ? 'domain' : 'unknown'
  # SIDs conhecidos (SYSTEM/serviços/anonimato) não identificam uma conta única
  # entre máquinas. Qualifica pelo host, assim como contas locais sem SID.
  principal = nil
  confidence = 'unknown'
  if name && domain && !local
    principal = "domain:#{domain}|#{name}"
    confidence = 'domain_name'
  elsif name && host_id
    principal = "host:#{host_id}|#{name}"
    confidence = 'host_name'
  elsif sid
    principal = well_known_sid && host_id ? "host:#{host_id}|sid:#{sid}" : "sid:#{sid}"
    confidence = 'sid'
  end
  return unless principal

  key = if sid
          well_known_sid && host_id ? "host:#{host_id}|sid:#{sid}" : "sid:#{sid}"
        else
          principal
        end
  account = @accounts.select do |candidate|
    (!present(candidate['sid']) || normalized(candidate['sid']) == sid) &&
      (!present(candidate['name']) || normalized(candidate['name']) == name) &&
      (!present(candidate['domain']) || normalized(candidate['domain']) == domain) &&
      (!present(candidate['host_id']) || normalized(candidate['host_id']) == host_id)
  end.max_by { |candidate| %w[sid name domain host_id].count { |field| present(candidate[field]) } }

  type = if account
           account['type']
         elsif name && name.end_with?('$')
           'machine'
         elsif system_domain || well_known_sid
           'system'
         else
           'unknown'
         end
  display = if account && present(account['label'])
              account['label']
            elsif name && domain
              "#{domain}\\#{name}"
            elsif name && host_name
              "#{host_name}\\#{name} (domínio desconhecido)"
            else
              name || sid
            end
  event.set('[user][name]', name) if name
  event.set('[user][domain]', domain) if domain
  event.set('[user][id]', sid.upcase) if sid
  event.set('[soc][identity][key]', key)
  event.set('[soc][identity][correlation_key]', principal)
  event.set('[soc][identity][display]', display)
  event.set('[soc][identity][scope]', scope)
  event.set('[soc][identity][type]', type)
  event.set('[soc][identity][confidence]', confidence)
  event.set('[soc][identity][has_sid]', !sid.nil?)
  event.set('[soc][identity][classification_source]', account ? 'catalog' : type == 'unknown' ? 'unknown' : 'well_known')
  admin = boolean(data['IsLocalAdmin'])
  event.set('[soc][identity][is_local_admin]', admin) unless admin.nil?
  if account
    event.set('[soc][identity][privileged]', account['privileged']) unless account['privileged'].nil?
    event.set('[soc][identity][owner]', account['owner']) if present(account['owner'])
  end
end

def elastic_metrics(event)
  nodes = event.get('[es_stats][nodes]')
  return [] unless nodes.is_a?(Hash) && !nodes.empty?
  # A consulta usa _local; manter um documento por nó/minuto sem somar snapshots.
  node_id, node = nodes.first
  event.set('[ecs][version]', '8.17.0')
  event.set('[event][kind]', 'metric')
  event.set('[event][category]', ['host'])
  event.set('[event][type]', ['info'])
  event.set('[event][module]', 'soc')
  event.set('[event][dataset]', 'soc.elasticsearch_capacity')
  event.set('[host][id]', node_id)
  event.set('[host][name]', node['name'])
  event.set('[soc][entity]', 'metric')
  event.set('[soc][metrics][source]', 'elasticsearch.capacity')
  paths = {
    'elastic_heap_used_bytes' => ['jvm', 'mem', 'heap_used_in_bytes'],
    'elastic_heap_max_bytes' => ['jvm', 'mem', 'heap_max_in_bytes'],
    'elastic_cpu_percent' => ['process', 'cpu', 'percent'],
    'elastic_fs_total_bytes' => ['fs', 'total', 'total_in_bytes'],
    'elastic_fs_available_bytes' => ['fs', 'total', 'available_in_bytes'],
    'elastic_store_bytes' => ['indices', 'store', 'size_in_bytes']
  }
  paths.each do |field, path|
    value = node.dig(*path)
    event.set("[soc][metrics][#{field}]", value) unless value.nil?
  end
  timestamp = event.get('@timestamp').time.utc
  event.set('[@metadata][doc_id]', "elasticsearch:#{node_id}:#{timestamp.strftime('%Y%m%d%H%M')}")
  event.set('[@metadata][index]', "soc-metrics-#{timestamp.strftime('%Y.%m')}")
  event.remove('es_stats')
  [event]
end

def filter(event)
  return elastic_metrics(event) if event.get('[@metadata][metric_input]') == 'elasticsearch'
  data = event.get('defender') || {}
  entity = event.get('[soc][entity]')
  dataset = event.get('[soc][dataset]')
  event.set('[ecs][version]', '8.17.0')
  # Horário de passagem pelo filtro; garantia de ingestão/atrasos fica fora desta rodada.
  event.set('[event][ingested]', LogStash::Timestamp.now)

  if entity == 'metric'
    event.set('[event][kind]', 'metric')
    event.set('[event][category]', ['database'])
    event.set('[event][type]', ['info'])
    event.set('[event][module]', 'soc')
    event.set('[event][dataset]', "soc.#{dataset}")
    data.each { |key, value| event.set("[soc][metrics][#{key}]", value) unless value.nil? }
    event.set('[@metadata][index]', "soc-metrics-#{event.get('@timestamp').time.utc.strftime('%Y.%m')}")
    return [event]
  end

  if entity == 'device' || entity == 'event'
    return [] unless in_scope(data['DeviceName'])
    event.set('[host][name]', normalized(data['DeviceName']))
    event.set('[host][id]', normalized(data['DeviceId'])) if present(data['DeviceId'])
    event.set('[soc][scope][included]', true)
  end

  if entity == 'device'
    event.set('[event][kind]', 'state')
    event.set('[event][category]', ['host'])
    event.set('[event][type]', ['info'])
    event.set('[event][module]', 'defender')
    event.set('[event][dataset]', 'defender.deviceinfo')
    map = {
      'SOCExpected' => 'expected', 'SOCObserved' => 'observed',
      'SOCOwner' => 'owner', 'SOCEnvironment' => 'environment', 'SOCCriticality' => 'criticality',
      'OnboardingStatus' => 'onboarding_status', 'SensorHealthState' => 'sensor_health',
      'DeviceType' => 'device_type', 'MachineGroup' => 'machine_group', 'OSPlatform' => 'os_platform',
      'Timestamp' => 'last_seen', 'SOCSnapshotAt' => 'snapshot_at'
    }
    map.each { |src, dst| event.set("[soc][asset][#{dst}]", data[src]) unless data[src].nil? || data[src] == '' }
    event.set('[@metadata][index]', 'soc-devices')
    if present(data['SOCSnapshotAt'])
      event.set('[@metadata][version]', (Time.parse(data['SOCSnapshotAt']).to_r * 1000).to_i.to_s)
    end
    return [event]
  end

  if entity == 'event'
    map = {
      'ActionType' => '[event][action]', 'LogonType' => '[winlog][logon][type]',
      'LogonId' => '[winlog][logon][id]', 'Protocol' => '[soc][logon][protocol]',
      'FailureReason' => '[event][reason]', 'FileName' => '[file][name]',
      'FolderPath' => '[file][path]', 'SHA256' => '[file][hash][sha256]',
      'InitiatingProcessFileName' => '[process][name]', 'InitiatingProcessCommandLine' => '[process][command_line]',
      'InitiatingProcessId' => '[process][pid]', 'InitiatingProcessAccountName' => '[process][user][name]',
      'InitiatingProcessParentFileName' => '[process][parent][name]'
    }
    prefix = dataset == 'devicelogonevents' ? '[source]' : '[destination]'
    map['RemoteIP'] = "#{prefix}[ip]"
    map['RemotePort'] = "#{prefix}[port]"
    map['RemoteDeviceName'] = "#{prefix}[domain]"
    map.each { |src, dst| event.set(dst, data[src]) unless data[src].nil? || data[src] == '' }
    identity(event, data)
    action = data['ActionType'].to_s
    if dataset == 'devicelogonevents'
      event.set('[event][category]', ['authentication'])
      event.set('[event][type]', ['start'])
      event.set('[event][outcome]', 'success') if action.start_with?('LogonSuccess')
      event.set('[event][outcome]', 'failure') if action.start_with?('LogonFailed')
    else
      event.set('[event][category]', ['process', 'intrusion_detection'])
      event.set('[event][type]', ['info'])
    end
    if action.start_with?('Asr')
      match = action.match(/\AAsr(.+?)(Audited|Blocked)?\z/)
      event.set('[soc][asr][rule]', match[1]) if match
      event.set('[soc][asr][mode]', match && match[2] == 'Audited' ? 'audit' : match && match[2] == 'Blocked' ? 'block' : 'other')
    end
    event.set('[event][kind]', 'event')
    event.set('[event][module]', 'defender')
    event.set('[event][dataset]', "defender.#{dataset}")
    event.set('[@metadata][index]', "soc-events-#{dataset}-#{event.get('@timestamp').time.utc.strftime('%Y.%m')}")
  elsif %w[incident alert incident_version alert_version].include?(entity)
    event.set('[soc][object][id]', data['id'])
    event.set('[soc][object][title]', data['displayName'] || data['title'])
    %w[status severity classification determination].each { |field| event.set("[soc][object][#{field}]", data[field]) unless data[field].nil? }
    event.set('[soc][object][assigned_to]', data['assignedTo']) unless data['assignedTo'].nil?
    event.set('[soc][object][service_source]', data['serviceSource']) unless data['serviceSource'].nil?
    event.set('[soc][object][incident_id]', data['incidentId'] || (dataset == 'incident' ? data['id'] : nil))
    url = data['incidentWebUrl'] || data['alertWebUrl']
    event.set('[soc][object][url]', url) unless url.nil?
    event.set('[soc][object][created]', data['createdDateTime']) unless data['createdDateTime'].nil?
    event.set('[event][severity_name]', data['severity']) unless data['severity'].nil?
    event.set('[event][kind]', 'alert')
    event.set('[event][category]', ['intrusion_detection'])
    event.set('[event][type]', ['info'])
    event.set('[event][module]', 'defender')
    event.set('[event][dataset]', "defender.#{dataset}")
    if %w[incident alert].include?(entity)
      event.set('[@metadata][index]', "soc-#{dataset}s")
      event.set('[@metadata][version]', (Time.parse(data['lastUpdateDateTime']).to_r * 1000).to_i.to_s) if data['lastUpdateDateTime']
    else
      event.set('[@metadata][index]', "soc-#{dataset}-history-#{event.get('@timestamp').time.utc.strftime('%Y.%m')}")
      event.remove('[@metadata][version]')
    end
  else
    event.set('[@metadata][index]', "soc-unknown-#{event.get('@timestamp').time.utc.strftime('%Y.%m')}")
  end
  [event]
end

test 'domínio normalizado correlaciona falha sem SID' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'devicelogonevents' }, 'defender' => { 'DeviceName' => 'SRV01.EXAMPLE', 'DeviceId' => 'd1', 'AccountName' => 'ADMIN', 'AccountDomain' => 'EXAMPLE', 'ActionType' => 'LogonFailed' } } }
  expect('chave nome/domínio e classificação não presumida') { |events| events.size == 1 && events[0].get('[soc][identity][correlation_key]') == 'domain:example|admin' && events[0].get('[soc][identity][type]') == 'unknown' }
end

test 'SID no sucesso mantém a mesma chave de correlação da falha' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'devicelogonevents' }, 'defender' => { 'DeviceName' => 'srv02', 'DeviceId' => 'd2', 'AccountName' => 'admin', 'AccountDomain' => 'example', 'AccountSid' => 'S-1-5-21-10-20-30-1001', 'ActionType' => 'LogonSuccess', 'IsLocalAdmin' => false } } }
  expect('SID principal e contexto booleano') { |events| events[0].get('[soc][identity][key]') == 'sid:s-1-5-21-10-20-30-1001' && events[0].get('[soc][identity][correlation_key]') == 'domain:example|admin' && events[0].get('[soc][identity][is_local_admin]') == false }
end

test 'conta local é qualificada pelo host' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'devicelogonevents' }, 'defender' => { 'DeviceName' => 'srv01.example', 'DeviceId' => 'd1', 'AccountName' => 'admin', 'AccountDomain' => 'SRV01' } } }
  expect('local não vira conta de domínio') { |events| events[0].get('[soc][identity][correlation_key]') == 'host:d1|admin' && events[0].get('[soc][identity][scope]') == 'local' }
end

test 'nome excluído prevalece sobre inclusão' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'deviceevents' }, 'defender' => { 'DeviceName' => 'SRV-NOTE-01' } } }
  expect('evento não é publicado') { |events| events.empty? }
end

test 'micro também prevalece em inventário' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'device' }, 'defender' => { 'DeviceName' => 'fisico-micro01' } } }
  expect('inventário fora do escopo não é publicado') { |events| events.empty? }
end

test 'SID SYSTEM é qualificado pelo dispositivo' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'devicelogonevents' }, 'defender' => { 'DeviceName' => 'fisico01', 'DeviceId' => 'd9', 'AccountName' => 'SYSTEM', 'AccountDomain' => 'NT AUTHORITY', 'AccountSid' => 'S-1-5-18' } } }
  expect('SYSTEM não é humano e não se mistura entre hosts') { |events| events[0].get('[soc][identity][key]') == 'host:d9|sid:s-1-5-18' && events[0].get('[soc][identity][type]') == 'system' }
end

test 'contas virtuais NT SERVICE não se misturam entre servidores' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    %w[srv01 srv02].map do |host|
      { 'soc' => { 'entity' => 'event', 'dataset' => 'devicelogonevents' },
        'defender' => { 'DeviceName' => host, 'DeviceId' => host, 'AccountName' => 'MSSQLSERVER',
          'AccountDomain' => 'NT SERVICE', 'AccountSid' => 'S-1-5-80-1-2-3-4-5' } }
    end
  end
  expect('correlação local é diferente por host') do |events|
    events.size == 2 && events.map { |e| e.get('[soc][identity][correlation_key]') }.uniq.size == 2 &&
      events.all? { |e| e.get('[soc][identity][scope]') == 'local' && e.get('[soc][identity][type]') == 'system' }
  end
end

test 'incidente não é restringido pelo nome do servidor' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'incident', 'dataset' => 'incident' }, 'defender' => { 'id' => 'i1', 'displayName' => 'Teste', 'lastUpdateDateTime' => '2026-10-21T12:00:00Z' } } }
  expect('estado atual conserva índice e versão externa') { |events| events.size == 1 && events[0].get('[@metadata][index]') == 'soc-incidents' && events[0].get('[@metadata][version]') == '1792584000000' }
end

test 'cadastro explícito classifica serviço sem inferir pelo nome' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'devicelogonevents' }, 'defender' => { 'DeviceName' => 'srv01', 'DeviceId' => 'd1', 'AccountName' => 'catalogued-service', 'AccountDomain' => 'example' } } }
  expect('classificação e privilégio vêm do catálogo') { |events| events[0].get('[soc][identity][type]') == 'service' && events[0].get('[soc][identity][classification_source]') == 'catalog' && events[0].get('[soc][identity][privileged]') == false }
end
