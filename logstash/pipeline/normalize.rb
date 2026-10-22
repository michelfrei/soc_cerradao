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

# O Graph devolve {} para datetime nulo (ex.: InitiatingProcessCreationTime): vazio é ausente.
def blank(value)
  value.nil? || value == '' || ((value.is_a?(Hash) || value.is_a?(Array)) && value.empty?)
end

def copy_fields(event, data, fields)
  fields.each { |src, dst| event.set(dst, data[src]) unless blank(data[src]) }
end

def executable_path(folder, name)
  folder = present(folder)
  name = present(name)
  return nil unless folder
  return folder unless name
  return folder if folder.split(/[\\\/]/).last.to_s.downcase == name.downcase
  folder.sub(/[\\\/]\z/, '') + (folder.include?('\\') ? '\\' : '/') + name
end

# UniqueId é da instância do processo. PID sozinho não é chave de correlação.
def process_fields(event, data, prefix = '', target = '[process]')
  map = prefix.empty? ? {
    'FileName' => 'name', 'ProcessCommandLine' => 'command_line', 'ProcessId' => 'pid',
    'ProcessCreationTime' => 'start', 'ProcessUniqueId' => 'entity_id',
    'SHA1' => 'hash][sha1', 'SHA256' => 'hash][sha256'
  } : {
    "#{prefix}FileName" => 'name', "#{prefix}CommandLine" => 'command_line', "#{prefix}Id" => 'pid',
    "#{prefix}CreationTime" => 'start', "#{prefix}UniqueId" => 'entity_id',
    "#{prefix}SHA1" => 'hash][sha1', "#{prefix}SHA256" => 'hash][sha256',
    "#{prefix}AccountName" => 'user][name', "#{prefix}AccountDomain" => 'user][domain',
    "#{prefix}AccountSid" => 'user][id'
  }
  copy_fields(event, data, map.transform_values { |dst| "#{target}[#{dst}]" })
  # 0 é o valor do Defender para instância/PID desconhecidos; não serve para correlação.
  event.remove("#{target}[entity_id]") if event.get("#{target}[entity_id]").to_s == '0'
  event.remove("#{target}[pid]") if event.get("#{target}[pid]").to_s == '0'
  event.remove("#{target}[start]") unless event.get("#{target}[start]").nil? || event.get("#{target}[start]").is_a?(String)
  executable = executable_path(data["#{prefix}FolderPath"], data["#{prefix}FileName"])
  event.set("#{target}[executable]", executable) if executable
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
  # Nomes genéricos (sem dono identificável) — revisão do papel cyber; comparação sem domínio.
  event.set('[soc][identity][generic]', name ? GENERIC_ACCOUNT.match?(name) : false)
  if account
    event.set('[soc][identity][privileged]', account['privileged']) unless account['privileged'].nil?
    event.set('[soc][identity][owner]', account['owner']) if present(account['owner'])
  end
end

GENERIC_ACCOUNT = /\A(administrator|administrador|admin|adm|root|guest|convidado|user|usuario|usuário|test|teste|temp|tmp|suporte|support|operador|scanner|backup|sa|sql|ti|infra|helpdesk)\d*\z/i

# Brasília (UTC-3, sem horário de verão desde 2019). Fora do horário: 22h–6h ou fim de semana.
LOCAL_OFFSET = -3 * 3600
def local_time(event)
  local = event.get('@timestamp').time.utc + LOCAL_OFFSET
  hour = local.hour
  weekend = local.saturday? || local.sunday?
  event.set('[soc][time][local_hour]', hour)
  event.set('[soc][time][local_weekday]', local.wday)
  event.set('[soc][time][weekend]', weekend)
  event.set('[soc][time][off_hours]', weekend || hour >= 22 || hour < 6)
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

  if %w[device event posture].include?(entity)
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
    internet_facing = boolean(data['IsInternetFacing'])
    event.set('[soc][asset][internet_facing]', internet_facing) unless internet_facing.nil?
    { 'ExposureLevel' => 'exposure_level', 'AssetValue' => 'asset_value' }.each do |src, dst|
      value = normalized(data[src])
      event.set("[soc][asset][#{dst}]", value) if value
    end
    event.set('[@metadata][index]', 'soc-devices')
    if present(data['SOCSnapshotAt'])
      event.set('[@metadata][version]', (Time.parse(data['SOCSnapshotAt']).to_r * 1000).to_i.to_s)
    end
    return [event]
  end

  if entity == 'insight'
    # Documento já estruturado pelo coletor (insights/engine.ts); só valida o contrato
    # mínimo e o leva à raiz. Versão externa evita regressão por execução antiga.
    generated = present(data['@timestamp'])
    return [] unless dataset == 'remediation' && present(data['insight_id']) && generated && present(data['schema_version'])
    data.each { |key, value| event.set("[#{key}]", value) unless key == '@timestamp' || value.nil? }
    event.remove('defender')
    event.set('[event][kind]', 'state')
    event.set('[event][module]', 'soc')
    event.set('[event][dataset]', 'soc.remediation_insight')
    event.set('[event][ingested]', LogStash::Timestamp.now)
    event.set('[@metadata][doc_id]', data['insight_id'])
    event.set('[@metadata][index]', 'soc-insights')
    event.set('[@metadata][version]', (Time.iso8601(generated).to_r * 1000).to_i.to_s)
    return [event]
  end

  if entity == 'posture'
    # O coletor publica somente snapshots completos com IDs estáveis. Não deixar
    # snapshot malformado escrever sem versão e sobrescrever estado mais recente.
    return [] unless %w[devicetvmsoftwarevulnerabilities devicetvmsecureconfigurationassessment devicetvmsoftwareinventory].include?(dataset)
    snapshot = present(data['SOCSnapshotAt'])
    active = boolean(data['SOCActive'])
    return [] unless snapshot && !active.nil? && present(data['DeviceId'])
    snapshot_time = Time.iso8601(snapshot)
    kind = { 'devicetvmsoftwarevulnerabilities' => 'vulnerability', 'devicetvmsoftwareinventory' => 'software' }.fetch(dataset, 'configuration')
    event.set('[event][kind]', 'state')
    event.set('[event][category]', [kind == 'vulnerability' ? 'vulnerability' : kind == 'software' ? 'package' : 'configuration'])
    event.set('[event][type]', ['info'])
    event.set('[event][module]', 'defender')
    event.set('[event][dataset]', "defender.#{dataset}")
    event.set('[soc][posture][active]', active)
    event.set('[soc][posture][state]', data['SOCState']) if present(data['SOCState'])
    event.set('[soc][posture][kind]', kind)
    event.set('[soc][posture][snapshot_at]', snapshot)
    if kind == 'vulnerability'
      copy_fields(event, data, {
        'CveId' => '[vulnerability][id]',
        'SoftwareName' => '[package][name]', 'SoftwareVersion' => '[package][version]',
        'SoftwareVendor' => '[soc][posture][software_vendor]'
      })
      begin
        score = Float(data['CvssScore'])
        event.set('[vulnerability][score][base]', score) if score.finite? && score.between?(0, 10)
      rescue ArgumentError, TypeError
        # Pontuação ausente/inválida fica somente no payload bruto; não é zero.
      end
      severity = normalized(data['VulnerabilitySeverityLevel'])
      event.set('[vulnerability][severity]', severity) if severity
      exploit = boolean(data['IsExploitAvailable'])
      event.set('[soc][posture][exploit_available]', exploit) unless exploit.nil?
    elsif kind == 'software'
      copy_fields(event, data, {
        'SoftwareName' => '[package][name]', 'SoftwareVersion' => '[package][version]',
        'SoftwareVendor' => '[soc][posture][software_vendor]',
        'EndOfSupportStatus' => '[soc][posture][end_of_support_status]'
      })
      eos_date = present(data['EndOfSupportDate'])
      begin
        event.set('[soc][posture][end_of_support_date]', Time.iso8601(eos_date).utc.iso8601) if eos_date
      rescue ArgumentError
        # Data inválida fica somente no payload bruto.
      end
    else
      copy_fields(event, data, {
        'ConfigurationId' => '[soc][posture][configuration_id]',
        'ConfigurationName' => '[soc][posture][configuration_name]',
        'ConfigurationCategory' => '[soc][posture][configuration_category]',
        'ConfigurationSubcategory' => '[soc][posture][configuration_subcategory]',
        'Timestamp' => '[soc][posture][assessed_at]'
      })
      { 'IsApplicable' => 'is_applicable', 'IsCompliant' => 'is_compliant' }.each do |src, dst|
        value = boolean(data[src])
        event.set("[soc][posture][#{dst}]", value) unless value.nil?
      end
      context = data['Context']
      if context.is_a?(String)
        begin
          context = JSON.parse(context)
        rescue JSON::ParserError
          context = { 'value' => context }
        end
      end
      context = { 'items' => context } unless context.nil? || context.is_a?(Hash)
      event.set('[soc][posture][context]', context) unless context.nil?
    end
    event.set('[@metadata][index]', 'soc-posture')
    event.set('[@metadata][version]', (snapshot_time.to_r * 1000).to_i.to_s)
    return [event]
  end

  if entity == 'event'
    local_time(event)
    map = {
      'ActionType' => '[event][action]', 'LogonType' => '[winlog][logon][type]',
      'LogonId' => '[winlog][logon][id]', 'Protocol' => '[soc][logon][protocol]',
      'FailureReason' => '[event][reason]', 'FileName' => '[file][name]',
      'FolderPath' => '[file][path]', 'SHA256' => '[file][hash][sha256]',
      'InitiatingProcessFileName' => '[process][name]', 'InitiatingProcessCommandLine' => '[process][command_line]',
      'InitiatingProcessId' => '[process][pid]', 'InitiatingProcessAccountName' => '[process][user][name]',
      'InitiatingProcessParentFileName' => '[process][parent][name]'
    }
    if dataset == 'devicelogonevents'
      map['RemoteIP'] = '[source][ip]'
      map['RemotePort'] = '[source][port]'
      map['RemoteDeviceName'] = '[source][domain]'
    end
    map.each { |src, dst| event.set(dst, data[src]) unless data[src].nil? || data[src] == '' }
    if dataset == 'deviceprocessevents'
      # O processo recém-criado não é o iniciador. Mantém ambos separadamente.
      event.remove('process')
      process_fields(event, data)
      process_fields(event, data, 'InitiatingProcess', '[process][parent]')
      copy_fields(event, data, { 'AccountName' => '[process][user][name]',
        'AccountDomain' => '[process][user][domain]', 'AccountSid' => '[process][user][id]' })
      identity(event, data)
    elsif dataset == 'devicenetworkevents'
      event.remove('process')
      process_fields(event, data, 'InitiatingProcess')
      account_data = data.merge('AccountName' => data['InitiatingProcessAccountName'],
        'AccountDomain' => data['InitiatingProcessAccountDomain'], 'AccountSid' => data['InitiatingProcessAccountSid'])
      account_data.delete('IsLocalAdmin')
      identity(event, account_data)
      copy_fields(event, data, {
        'LocalIP' => '[soc][network][local_ip]', 'LocalPort' => '[soc][network][local_port]',
        'RemoteIP' => '[soc][network][remote_ip]', 'RemotePort' => '[soc][network][remote_port]',
        'RemoteUrl' => '[soc][network][remote_url]', 'LocalIPType' => '[soc][network][local_ip_type]',
        'RemoteIPType' => '[soc][network][remote_ip_type]'
      })
      protocol = normalized(data['Protocol'])
      event.set('[network][transport]', protocol) if protocol
      # Local/remoto é perspectiva do sensor, não prova direção da conexão.
      event.remove('[soc][logon]')
    else
      identity(event, data)
    end
    action = data['ActionType'].to_s
    if dataset == 'devicelogonevents'
      event.set('[event][category]', ['authentication'])
      event.set('[event][type]', ['start'])
      event.set('[event][outcome]', 'success') if action.start_with?('LogonSuccess')
      event.set('[event][outcome]', 'failure') if action.start_with?('LogonFailed')
    elsif dataset == 'deviceprocessevents'
      event.set('[event][category]', ['process'])
      event.set('[event][type]', action == 'ProcessCreated' ? ['start'] : ['info'])
    elsif dataset == 'devicenetworkevents'
      event.set('[event][category]', ['network'])
      event.set('[event][type]', ['info'])
    elsif action.start_with?('Asr')
      event.set('[event][category]', ['process', 'intrusion_detection'])
      event.set('[event][type]', ['info'])
    else
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

test 'processo criado fica em process e iniciador em parent' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    { 'soc' => { 'entity' => 'event', 'dataset' => 'deviceprocessevents' }, 'defender' => {
      'DeviceName' => 'SRV-PROCESS', 'DeviceId' => 'D-PROCESS', 'ActionType' => 'ProcessCreated',
      'FileName' => 'powershell.exe', 'FolderPath' => 'C:\\Windows', 'ProcessCommandLine' => 'powershell -nop',
      'ProcessId' => 100, 'ProcessUniqueId' => 'created-100', 'ProcessCreationTime' => '2026-10-21T12:00:00Z',
      'SHA1' => 'abc', 'SHA256' => 'def', 'AccountName' => 'child-account', 'AccountDomain' => 'example',
      'InitiatingProcessFileName' => 'cmd.exe', 'InitiatingProcessId' => 90,
      'InitiatingProcessUniqueId' => 'parent-90', 'InitiatingProcessAccountName' => 'parent-account' } }
  end
  expect('processos, identidades e categoria não se confundem') do |events|
    e = events.first
    e.get('[process][name]') == 'powershell.exe' && e.get('[process][parent][name]') == 'cmd.exe' &&
      e.get('[process][entity_id]') == 'created-100' && e.get('[process][parent][entity_id]') == 'parent-90' &&
      e.get('[process][executable]') == 'C:\\Windows\\powershell.exe' &&
      e.get('[process][hash][sha1]') == 'abc' && e.get('[process][hash][sha256]') == 'def' &&
      e.get('[user][name]') == 'child-account' && e.get('[process][parent][user][name]') == 'parent-account' &&
      e.get('[event][category]') == ['process'] && e.get('[event][type]') == ['start']
  end
end

test 'PID sem UniqueId não inventa identidade da instância' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'deviceprocessevents' }, 'defender' => { 'DeviceName' => 'srv01', 'ProcessId' => 10, 'InitiatingProcessId' => 5 } } }
  expect('entity_id permanece ausente') { |events| events[0].get('[process][pid]') == 10 && events[0].get('[process][entity_id]').nil? && events[0].get('[process][parent][entity_id]').nil? }
end

test 'rede usa processo e conta iniciadores e endpoints locais e remotos sem direção presumida' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    { 'soc' => { 'entity' => 'event', 'dataset' => 'devicenetworkevents' }, 'defender' => {
      'DeviceName' => 'fisico01', 'DeviceId' => 'd1', 'ActionType' => 'ConnectionSuccess', 'Protocol' => 'Tcp',
      'LocalIP' => '10.0.0.1', 'LocalPort' => 53000, 'RemoteIP' => '203.0.113.1', 'RemotePort' => 443,
      'RemoteUrl' => 'example.test', 'LocalIPType' => 'Private', 'RemoteIPType' => 'Public',
      'AccountName' => 'wrong-account', 'AccountDomain' => 'wrong-domain',
      'InitiatingProcessFileName' => 'browser.exe', 'InitiatingProcessUniqueId' => 'network-process',
      'InitiatingProcessAccountName' => 'network-user', 'InitiatingProcessAccountDomain' => 'example' } }
  end
  expect('perspectiva local, identidade iniciadora e categoria rede') do |events|
    e = events.first
    e.get('[soc][network][local_ip]') == '10.0.0.1' && e.get('[soc][network][remote_port]') == 443 &&
      e.get('[soc][network][remote_url]') == 'example.test' && e.get('[network][transport]') == 'tcp' &&
      e.get('[user][name]') == 'network-user' && e.get('[process][entity_id]') == 'network-process' &&
      e.get('[event][category]') == ['network'] && e.get('[event][outcome]').nil? &&
      e.get('[network][direction]').nil? && e.get('[network][bytes]').nil? &&
      e.get('[source][ip]').nil? && e.get('[destination][ip]').nil?
  end
end

test 'evento genérico não é classificado como detecção de intrusão' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'deviceevents' }, 'defender' => { 'DeviceName' => 'srv01', 'ActionType' => 'SomeOtherEvent' } } }
  expect('sem categoria inferida') { |events| events[0].get('[event][category]').nil? }
end

test 'ASR preserva a categoria específica' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'event', 'dataset' => 'deviceevents' }, 'defender' => { 'DeviceName' => 'srv01', 'ActionType' => 'AsrOfficeChildProcessBlocked' } } }
  expect('categoria e modo do evento ASR') { |events| events[0].get('[event][category]').include?('intrusion_detection') && events[0].get('[soc][asr][mode]') == 'block' }
end

test 'postura vulnerabilidade preserva ausência de exploit e pontuação' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    { '@metadata' => { 'doc_id' => 'stable-vulnerability' }, 'soc' => { 'entity' => 'posture', 'dataset' => 'devicetvmsoftwarevulnerabilities' },
      'defender' => { 'DeviceName' => 'srv01', 'DeviceId' => 'd1', 'CveId' => 'CVE-2099-0001',
        'VulnerabilitySeverityLevel' => 'Critical', 'SoftwareName' => 'app', 'SoftwareVersion' => '1',
        'SOCActive' => true, 'SOCState' => 'observed', 'SOCSnapshotAt' => '2026-10-21T12:00:00Z' } }
  end
  expect('índice atual versionado, chave estável e campos opcionais desconhecidos') do |events|
    e = events.first
    e.get('[@metadata][index]') == 'soc-posture' && e.get('[@metadata][doc_id]') == 'stable-vulnerability' &&
      e.get('[@metadata][version]') == '1792584000000' && e.get('[soc][posture][active]') == true &&
      e.get('[soc][posture][kind]') == 'vulnerability' && e.get('[vulnerability][severity]') == 'critical' &&
      e.get('[package][name]') == 'app' && e.get('[soc][posture][exploit_available]').nil? &&
      e.get('[vulnerability][score][base]').nil?
  end
end

test 'postura configuração conserva falsos e contexto JSON' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    { 'soc' => { 'entity' => 'posture', 'dataset' => 'devicetvmsecureconfigurationassessment' }, 'defender' => {
      'DeviceName' => 'fisico01', 'DeviceId' => 'd1', 'ConfigurationId' => 'scid-test', 'ConfigurationName' => 'Test',
      'ConfigurationCategory' => 'SecurityControls', 'IsApplicable' => true, 'IsCompliant' => false,
      'Timestamp' => '2026-10-20T11:00:00Z',
      'Context' => '[{"av":"passive"}]', 'SOCActive' => true, 'SOCState' => 'observed', 'SOCSnapshotAt' => '2026-10-21T12:00:00Z' } }
  end
  expect('falso não vira desconhecido e contexto é objeto para flattened') do |events|
    e = events.first
    e.get('[soc][posture][is_compliant]') == false && e.get('[soc][posture][is_applicable]') == true &&
      e.get('[soc][posture][context][items]')[0]['av'] == 'passive' &&
      e.get('[soc][posture][configuration_id]') == 'scid-test' &&
      e.get('[soc][posture][assessed_at]') == '2026-10-20T11:00:00Z' &&
      e.get('[soc][posture][snapshot_at]') == '2026-10-21T12:00:00Z'
  end
end

test 'CVSS numérico válido é convertido e inválido não é inventado como zero' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    ['9.8', 'N/A', 0, 11].map do |score|
      { 'soc' => { 'entity' => 'posture', 'dataset' => 'devicetvmsoftwarevulnerabilities' },
        'defender' => { 'DeviceName' => 'srv01', 'DeviceId' => 'd1', 'CvssScore' => score,
          'SOCActive' => true, 'SOCSnapshotAt' => '2026-10-21T12:00:00Z' } }
    end
  end
  expect('somente valores finitos entre zero e dez no campo numérico') do |events|
    events[0].get('[vulnerability][score][base]') == 9.8 &&
      events[1].get('[vulnerability][score][base]').nil? &&
      events[1].get('[defender][CvssScore]') == 'N/A' &&
      events[2].get('[vulnerability][score][base]') == 0.0 &&
      events[3].get('[vulnerability][score][base]').nil?
  end
end

test 'tombstone de postura é estado retirado, não resolução comprovada' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    { 'soc' => { 'entity' => 'posture', 'dataset' => 'devicetvmsoftwarevulnerabilities' }, 'defender' => {
      'DeviceName' => 'srv01', 'DeviceId' => 'd1', 'CveId' => 'CVE-2099-0002',
      'SOCActive' => false, 'SOCState' => 'no_longer_reported', 'SOCSnapshotAt' => '2026-10-21T13:00:00Z' } }
  end
  expect('não perde falso nem inventa remediação') { |events| events[0].get('[soc][posture][active]') == false && events[0].get('[soc][posture][state]') == 'no_longer_reported' && events[0].get('[@metadata][version]') == '1792587600000' }
end

test 'postura fora do escopo não é publicada' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'posture' }, 'defender' => { 'DeviceName' => 'srv-note-excluded' } } }
  expect('note prevalece no snapshot também') { |events| events.empty? }
end

test 'postura sem snapshot ou estado conhecido não sobrescreve índice atual' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event { { 'soc' => { 'entity' => 'posture', 'dataset' => 'devicetvmsoftwarevulnerabilities' }, 'defender' => { 'DeviceName' => 'srv01', 'DeviceId' => 'd1', 'SOCActive' => true } } }
  expect('não publica snapshot sem versão') { |events| events.empty? }
end

test 'inventário tem exposição opcional sem tratar desconhecido como falso' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    [ { 'DeviceName' => 'srv01', 'ExposureLevel' => 'High', 'AssetValue' => 'High', 'IsInternetFacing' => true },
      { 'DeviceName' => 'srv02' } ].map { |d| { 'soc' => { 'entity' => 'device' }, 'defender' => d } }
  end
  expect('exposição normalizada e ausência preservada') do |events|
    events[0].get('[soc][asset][exposure_level]') == 'high' && events[0].get('[soc][asset][internet_facing]') == true &&
      events[1].get('[soc][asset][internet_facing]').nil? && events[1].get('[soc][asset][exposure_level]').nil?
  end
end

test 'hora local de Brasília, fora do horário e conta genérica' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    [ ['2026-10-21T12:00:00Z', 'Administrador'], ['2026-10-22T03:30:00Z', 'joao.silva'], ['2026-10-24T15:00:00Z', 'admin2'] ].map do |ts, account|
      { '@timestamp' => ts, 'soc' => { 'entity' => 'event', 'dataset' => 'devicelogonevents' },
        'defender' => { 'DeviceName' => 'srv01', 'DeviceId' => 'd1', 'AccountName' => account, 'AccountDomain' => 'example', 'ActionType' => 'LogonSuccess' } }
    end
  end
  expect('quarta 09h dentro do horário; quinta 00h30 fora; sábado fora') do |events|
    events[0].get('[soc][time][local_hour]') == 9 && events[0].get('[soc][time][off_hours]') == false &&
      events[1].get('[soc][time][local_hour]') == 0 && events[1].get('[soc][time][off_hours]') == true &&
      events[2].get('[soc][time][weekend]') == true && events[2].get('[soc][time][off_hours]') == true
  end
  expect('nomes genéricos sem considerar caixa ou sufixo numérico') do |events|
    events[0].get('[soc][identity][generic]') == true && events[1].get('[soc][identity][generic]') == false &&
      events[2].get('[soc][identity][generic]') == true
  end
end

test 'insight de remediação vai à raiz com versão externa e ID estável' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    [ { 'soc' => { 'entity' => 'insight', 'dataset' => 'remediation' }, 'defender' => {
        '@timestamp' => '2026-10-22T12:00:00.000Z', 'schema_version' => '1.0', 'insight_id' => 'ins-abc',
        'title' => 'Atualizar app', 'category' => 'application_update', 'priority' => 'P1',
        'source' => { 'name' => 'microsoft-defender-vulnerability-management', 'finding_ids' => ['p1'] },
        'internet_facing_device_count' => nil, 'affected_device_count' => 2 } },
      { 'soc' => { 'entity' => 'insight', 'dataset' => 'remediation' }, 'defender' => { 'title' => 'sem id' } } ]
  end
  expect('documento estruturado, sem payload bruto e inválido descartado') do |events|
    e = events.first
    events.length == 1 && e.get('[@metadata][index]') == 'soc-insights' && e.get('[@metadata][doc_id]') == 'ins-abc' &&
      e.get('[@metadata][version]') == '1792670400000' && e.get('[category]') == 'application_update' &&
      e.get('[source][finding_ids]') == ['p1'] && e.get('[affected_device_count]') == 2 &&
      e.get('[internet_facing_device_count]').nil? && e.get('defender').nil? && e.get('[event][dataset]') == 'soc.remediation_insight'
  end
end

test 'postura de software preserva fim de suporte' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    { 'soc' => { 'entity' => 'posture', 'dataset' => 'devicetvmsoftwareinventory' }, 'defender' => {
      'DeviceName' => 'srv01', 'DeviceId' => 'd1', 'SoftwareVendor' => 'oracle', 'SoftwareName' => 'jre', 'SoftwareVersion' => '7',
      'EndOfSupportStatus' => 'EOS Software', 'EndOfSupportDate' => '2022-07-19T00:00:00Z',
      'SOCActive' => true, 'SOCState' => 'observed', 'SOCSnapshotAt' => '2026-10-21T12:00:00Z' } }
  end
  expect('tipo software, pacote e data de fim de suporte') do |events|
    e = events.first
    e.get('[soc][posture][kind]') == 'software' && e.get('[event][category]') == ['package'] &&
      e.get('[package][name]') == 'jre' && e.get('[soc][posture][end_of_support_status]') == 'EOS Software' &&
      e.get('[soc][posture][end_of_support_date]') == '2022-07-19T00:00:00Z' && e.get('[@metadata][index]') == 'soc-posture'
  end
end

test 'datetime nulo do Graph ({}) e IDs zero não viram campos inválidos' do
  parameters { { 'identities_path' => '/usr/share/logstash/pipeline/normalize-test-identities.json' } }
  in_event do
    { 'soc' => { 'entity' => 'event', 'dataset' => 'devicenetworkevents' }, 'defender' => {
      'DeviceName' => 'srv02fisico', 'DeviceId' => 'd1', 'ActionType' => 'ConnectionAcknowledged', 'Protocol' => 'TcpV4',
      'InitiatingProcessCreationTime' => {}, 'InitiatingProcessParentCreationTime' => {},
      'InitiatingProcessUniqueId' => '0', 'InitiatingProcessId' => 0, 'RemoteIP' => '203.0.113.1', 'RemotePort' => 443 } }
  end
  expect('sem process.start/entity_id/pid quando desconhecidos') do |events|
    e = events.first
    e.get('[process][start]').nil? && e.get('[process][entity_id]').nil? && e.get('[process][pid]').nil? &&
      e.get('[process][parent][start]').nil? && e.get('[soc][network][remote_port]') == 443
  end
end
