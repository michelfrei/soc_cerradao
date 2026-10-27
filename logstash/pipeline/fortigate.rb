# Logs do FortiGate encaminhados pelo FortiAnalyzer (syslog, formato chave=valor).
# Converte para ECS e guarda só os campos mapeados em fw-logs-mappings.json; o resto
# (identificadores internos, horários duplicados, MAC "master" etc.) é descartado.
# Os testes abaixo rodam no registro do filtro e com --config.test_and_exit.
require 'time'

KV = /([A-Za-z0-9_-]+)=("(?:[^"\\]|\\.)*"|[^\s"]*)/

# Chave do FortiOS → campo ECS (ou fortinet.firewall.*). Tipo :int converte número.
FIELDS = {
  'logid' => '[event][code]', 'level' => '[log][level]', 'devname' => '[observer][name]', 'devid' => '[observer][serial_number]',
  'vd' => '[fortinet][firewall][vd]', 'subtype' => '[fortinet][firewall][subtype]', 'action' => '[event][action]',
  'policyid' => '[rule][id]', 'policyname' => '[rule][name]', 'poluuid' => '[rule][uuid]', 'policytype' => '[rule][ruleset]',
  'srcip' => '[source][ip]', 'srcport' => ['[source][port]', :int], 'srcmac' => '[source][mac]',
  'srcname' => '[fortinet][firewall][srcname]', 'srcintf' => '[observer][ingress][interface][name]',
  'srcintfrole' => '[fortinet][firewall][srcintfrole]', 'srchwvendor' => '[fortinet][firewall][srchwvendor]',
  'osname' => '[fortinet][firewall][osname]', 'devtype' => '[fortinet][firewall][devtype]',
  'dstip' => '[destination][ip]', 'dstport' => ['[destination][port]', :int], 'dstintf' => '[observer][egress][interface][name]',
  'dstintfrole' => '[fortinet][firewall][dstintfrole]', 'hostname' => '[destination][domain]',
  'dstowner' => '[fortinet][firewall][dstowner]', 'dstreputation' => ['[fortinet][firewall][dstreputation]', :int],
  'transip' => '[source][nat][ip]', 'transport' => ['[source][nat][port]', :int], 'trandisp' => '[fortinet][firewall][trandisp]',
  'tranip' => '[destination][nat][ip]', 'tranport' => ['[destination][nat][port]', :int],
  'service' => '[fortinet][firewall][service]', 'app' => '[network][application]', 'appcat' => '[fortinet][firewall][appcat]',
  'catdesc' => '[fortinet][firewall][catdesc]', 'utmaction' => '[fortinet][firewall][utmaction]',
  'sentbyte' => ['[source][bytes]', :int], 'rcvdbyte' => ['[destination][bytes]', :int],
  'sentpkt' => ['[source][packets]', :int], 'rcvdpkt' => ['[destination][packets]', :int],
  'sessionid' => '[fortinet][firewall][sessionid]', 'user' => '[user][name]', 'group' => '[user][group][name]',
  'unauthuser' => '[fortinet][firewall][unauthuser]', 'vwlname' => '[fortinet][firewall][sdwan_rule]',
  'crscore' => ['[fortinet][firewall][crscore]', :int],
  # UTM e eventos de sistema/VPN
  'url' => '[url][original]', 'attack' => '[fortinet][firewall][attack]', 'virus' => '[fortinet][firewall][virus]',
  'severity' => '[fortinet][firewall][severity]', 'msg' => '[message]', 'logdesc' => '[fortinet][firewall][logdesc]',
  'eventtype' => '[fortinet][firewall][eventtype]', 'profile' => '[fortinet][firewall][profile]',
  'ui' => '[fortinet][firewall][ui]', 'status' => '[fortinet][firewall][status]', 'reason' => '[fortinet][firewall][reason]',
  'tunneltype' => '[fortinet][firewall][tunneltype]', 'remip' => '[fortinet][firewall][remip]',
  'tunnelid' => '[fortinet][firewall][tunnelid]', 'tunnelip' => '[fortinet][firewall][tunnelip]',
  'vpntunnel' => '[fortinet][firewall][vpntunnel]', 'xauthuser' => '[fortinet][firewall][xauthuser]',
  'method' => '[fortinet][firewall][method]', 'sn' => '[fortinet][firewall][sn]',
}.freeze

PROTOCOLS = { 1 => 'icmp', 6 => 'tcp', 17 => 'udp', 47 => 'gre', 50 => 'esp', 58 => 'ipv6-icmp', 132 => 'sctp' }.freeze
BLOCKED_ACTIONS = %w[deny block blocked dropped drop reset].freeze
UNKNOWN_COUNTRY = %w[reserved undefined].freeze

def register(_params); end

def parse_kv(text)
  out = {}
  text.scan(KV) do |key, raw|
    value = raw.start_with?('"') ? raw[1..-2].gsub(/\\(.)/, '\1') : raw
    out[key] = value unless value.empty? || value == 'N/A'
  end
  out
end

# eventtime vem em s, ms, µs ou ns conforme a versão do FortiOS.
def event_time(data)
  if data['eventtime'] =~ /\A\d+\z/
    n = data['eventtime'].to_i
    digits = data['eventtime'].length
    sec, nsec = if digits >= 18 then n.divmod(1_000_000_000)
                elsif digits >= 15 then [n / 1_000_000, (n % 1_000_000) * 1000]
                elsif digits >= 12 then [n / 1000, (n % 1000) * 1_000_000]
                else [n, 0]
                end
    return Time.at(sec, nsec, :nsec).utc
  end
  return nil unless data['date'] && data['time']
  tz = data['tz'] =~ /\A[+-]\d{4}\z/ ? "#{data['tz'][0, 3]}:#{data['tz'][3, 2]}" : '-03:00'
  Time.iso8601("#{data['date']}T#{data['time']}#{tz}").utc
rescue ArgumentError
  nil
end

def direction(src_role, dst_role)
  return 'unknown' unless src_role && dst_role
  return 'outbound' if src_role != 'wan' && dst_role == 'wan'
  return 'inbound' if src_role == 'wan' && dst_role != 'wan'
  return 'internal' if src_role != 'wan' && dst_role != 'wan' && src_role != 'undefined' && dst_role != 'undefined'
  'unknown'
end

# Acesso administrativo (login/logout no FortiGate) e VPN. soc.fw.session.id liga a
# abertura ao fechamento (sn do login admin, tunnelid da VPN) para o estado das sessões
# calculado pelo coletor (fwsessions).
VPN_FAILURES = %w[ssl-login-fail negotiate-error tunnel-fail].freeze

def access(event, data)
  return unless data['type'] == 'event'
  action = data['action'].to_s.downcase
  status = data['status'].to_s.downcase
  devid = data['devid']
  if data['subtype'] == 'system' && %w[login logout].include?(action) && data['user']
    ok = status == 'success'
    channel = data['ui'].to_s[/\A([a-z_]+)/, 1] || data['method']
    remote = data['ui'].to_s[/\(([0-9a-fA-F.:]+)\)/, 1]
    event.set('[source][ip]', remote) if !data['srcip'] && remote
    event.set('[soc][fw][access][kind]', 'admin')
    event.set('[soc][fw][access][user]', data['user'])
    event.set('[soc][fw][access][channel]', channel) if channel
    event.set('[event][category]', ['authentication'])
    event.set('[event][type]', [action == 'login' ? 'start' : 'end'])
    event.set('[event][outcome]', ok ? 'success' : 'failure')
    event.set('[soc][fw][access][outcome]', ok ? 'success' : 'failure')
    key = data['sn'] ? "admin|#{devid}|#{data['sn']}" : "admin|#{devid}|#{data['user']}|#{data['ui']}"
    if ok
      event.set('[soc][fw][session][id]', key)
      event.set('[soc][fw][session][state]', action == 'login' ? 'open' : 'close')
    end
  elsif data['subtype'] == 'vpn'
    tunnel = data['tunneltype'].to_s.downcase
    kind = tunnel.start_with?('ssl') ? 'ssl' : (tunnel.include?('ipsec') || data['vpntunnel'] ? 'ipsec' : 'outro')
    user = data['user'] || data['xauthuser']
    failed = VPN_FAILURES.include?(action) || %w[failure failed].include?(status)
    event.set('[soc][fw][access][kind]', 'vpn')
    event.set('[soc][fw][access][channel]', kind)
    event.set('[soc][fw][access][user]', user) if user
    if failed || action == 'tunnel-up'
      event.set('[soc][fw][access][outcome]', failed ? 'failure' : 'success')
      event.set('[event][category]', ['authentication', 'network'])
      event.set('[event][outcome]', failed ? 'failure' : 'success')
    end
    state = { 'tunnel-up' => 'open', 'tunnel-down' => 'close', 'tunnel-stats' => 'alive' }[action]
    key = if data['tunnelid'] then "vpn|#{devid}|#{data['tunnelid']}"
          elsif data['vpntunnel'] && data['remip'] then "vpn|#{devid}|#{data['vpntunnel']}|#{data['remip']}"
          end
    if state && key && !failed
      event.set('[soc][fw][session][id]', key)
      event.set('[soc][fw][session][state]', state)
    end
  end
end

def filter(event)
  message = event.get('message').to_s.sub(/\A\s*<\d{1,3}>/, '')
  data = parse_kv(message)
  type = data['type']
  return [] unless type && data['devid'] # não é log do FortiGate: descarta

  event.remove('message')
  %w[host @version event].each { |f| event.remove(f) }
  FIELDS.each do |key, target|
    value = data[key]
    next unless value
    path, kind = target.is_a?(Array) ? target : [target, nil]
    if kind == :int
      next unless value =~ /\A-?\d+\z/
      value = value.to_i
    end
    event.set(path, value)
  end
  %w[srccountry dstcountry].each do |key|
    next unless data[key] && !UNKNOWN_COUNTRY.include?(data[key].downcase)
    event.set(key == 'srccountry' ? '[source][geo][country_name]' : '[destination][geo][country_name]', data[key])
  end
  # VPN e login de administrador trazem a origem em remip.
  event.set('[source][ip]', data['remip']) if !data['srcip'] && data['remip']

  if data['proto'] =~ /\A\d+\z/
    event.set('[network][iana_number]', data['proto'])
    event.set('[network][transport]', PROTOCOLS.fetch(data['proto'].to_i, data['proto']))
  end
  bytes = %w[sentbyte rcvdbyte].map { |k| data[k].to_s =~ /\A\d+\z/ ? data[k].to_i : nil }.compact
  event.set('[network][bytes]', bytes.sum) unless bytes.empty?
  packets = %w[sentpkt rcvdpkt].map { |k| data[k].to_s =~ /\A\d+\z/ ? data[k].to_i : nil }.compact
  event.set('[network][packets]', packets.sum) unless packets.empty?
  event.set('[event][duration]', data['duration'].to_i * 1_000_000_000) if data['duration'] =~ /\A\d+\z/
  event.set('[network][direction]', direction(data['srcintfrole'], data['dstintfrole']))

  event.set('[fortinet][firewall][type]', type)
  event.set('[event][kind]', 'event')
  event.set('[event][module]', 'fortigate')
  event.set('[event][dataset]', "fortigate.#{type}")
  event.set('[observer][vendor]', 'Fortinet')
  event.set('[observer][product]', 'FortiGate')
  event.set('[observer][type]', 'firewall')
  event.set('[ecs][version]', '8.17.0')
  event.set('[event][ingested]', LogStash::Timestamp.now)
  if %w[traffic utm].include?(type)
    blocked = BLOCKED_ACTIONS.include?(data['action'].to_s.downcase) || BLOCKED_ACTIONS.include?(data['utmaction'].to_s.downcase)
    event.set('[soc][fw][verdict]', blocked ? 'blocked' : 'allowed')
    event.set('[event][category]', ['network'])
    event.set('[event][type]', ['connection', blocked ? 'denied' : 'allowed'])
  end
  access(event, data)
  time = event_time(data)
  if time
    event.set('@timestamp', LogStash::Timestamp.new(time))
  else
    event.tag('_fortigate_sem_horario')
  end
  [event]
end

SAMPLE = '<189>date=2026-10-27 time=14:56:12 id=7701407958453715280 itime="2026-10-27 10:56:12" logver=704112878 type="traffic" ' \
  'subtype="forward" level="notice" action="server-rst" utmaction="block" policyid=151 sessionid=545051130 srcip=10.20.15.99 ' \
  'dstip=17.250.104.75 transip=200.0.2.1 srcport=50242 dstport=443 transport=11051 trandisp="snat" duration=5 proto=6 ' \
  'sentbyte=144 rcvdbyte=140 sentpkt=3 rcvdpkt=3 logid=0000000013 service="Apple-Web" app="Apple-Web" appcat="unscanned" ' \
  'srcintfrole="lan" dstintfrole="wan" eventtime=1793123772451556480 srcmac="be:c9:4c:00:00:01" mastersrcmac="be:c9:4c:00:00:01" ' \
  'srccountry="Reserved" dstcountry="Brazil" srcintf="VLAN-112" dstintf="VLAN-1001" policyname="TEMP SAIDA" ' \
  'vwlquality="Seq_num(2 VLAN-1001 SDWAN-ALGAR), alive, selected" user="fulano" catdesc="SITES_BLOQUEADOS" tz="-0300" ' \
  'devid="FG100FTK00000000" vd="root" devname="CERRADAO_FG100F"'

test 'tráfego encaminhado vira ECS com horário de eventtime e veredito' do
  in_event { { 'message' => SAMPLE } }
  expect('campos principais') do |events|
    e = events[0]
    events.size == 1 && e.get('[source][ip]') == '10.20.15.99' && e.get('[destination][port]') == 443 &&
      e.get('[source][nat][ip]') == '200.0.2.1' && e.get('[network][transport]') == 'tcp' && e.get('[network][bytes]') == 284 &&
      e.get('[network][direction]') == 'outbound' && e.get('[soc][fw][verdict]') == 'blocked' &&
      e.get('[event][dataset]') == 'fortigate.traffic' && e.get('[rule][id]') == '151' && e.get('[rule][name]') == 'TEMP SAIDA' &&
      e.get('[observer][name]') == 'CERRADAO_FG100F' && e.get('[user][name]') == 'fulano' &&
      e.get('@timestamp').to_i == 1793123772 && e.get('@timestamp').time.usec == 451556 && e.get('[event][duration]') == 5_000_000_000
  end
  expect('descarta redundantes, país reservado e a mensagem original') do |events|
    e = events[0]
    e.get('message').nil? && e.get('[source][geo][country_name]').nil? && e.get('[destination][geo][country_name]') == 'Brazil' &&
      e.get('[fortinet][firewall][vwlquality]').nil? && e.get('[fortinet][firewall][itime]').nil? && e.get('id').nil?
  end
end

test 'aceito sem UTM é allowed; sem eventtime usa date/time/tz' do
  in_event { { 'message' => 'date=2026-10-27 time=08:00:00 tz="-0300" type="traffic" action="accept" devid="FG1" srcintfrole="wan" dstintfrole="lan"' } }
  expect('veredito, direção e horário') do |events|
    e = events[0]
    e.get('[soc][fw][verdict]') == 'allowed' && e.get('[network][direction]') == 'inbound' && e.get('@timestamp').to_i == Time.iso8601('2026-10-27T11:00:00Z').to_i
  end
end

test 'evento de VPN usa remip como origem; linha que não é do FortiGate é descartada' do
  in_event do
    [{ 'message' => '<190>date=2026-10-27 time=09:00:00 type="event" subtype="vpn" action="tunnel-up" remip=203.0.113.5 user="u1" devid="FG1" msg="SSL tunnel established"' },
     { 'message' => 'lixo sem chave' }]
  end
  expect('um evento, origem remip, mensagem preservada') do |events|
    events.size == 1 && events[0].get('[source][ip]') == '203.0.113.5' && events[0].get('[message]') == 'SSL tunnel established' &&
      events[0].get('[soc][fw][verdict]').nil? && events[0].get('[event][dataset]') == 'fortigate.event'
  end
end

test 'aspas escapadas e valor numérico inválido' do
  in_event { { 'message' => 'type="traffic" devid="FG1" srcport=abc policyname="a \"b\" c" action="deny"' } }
  expect('porta inválida ausente, nome sem barras') do |events|
    e = events[0]
    e.get('[source][port]').nil? && e.get('[rule][name]') == 'a "b" c' && e.get('[soc][fw][verdict]') == 'blocked'
  end
end

test 'login de administrador: sucesso abre sessão pelo sn; falha não abre; logout fecha' do
  in_event do
    base = 'date=2026-10-27 time=10:00:00 tz="-0300" type="event" subtype="system" devid="FG1" logid="0100032001" '
    [{ 'message' => base + 'action="login" status="success" user="admin" ui="https(10.0.0.5)" method="https" profile="super_admin" sn="1793"' },
     { 'message' => base + 'action="login" status="failed" user="root" ui="ssh(203.0.113.9)" reason="name_invalid"' },
     { 'message' => base + 'action="logout" status="success" user="admin" ui="https(10.0.0.5)" sn="1793"' }]
  end
  expect('classificação, origem e chave de sessão') do |events|
    ok, bad, out = events
    ok.get('[soc][fw][access][kind]') == 'admin' && ok.get('[soc][fw][access][channel]') == 'https' && ok.get('[source][ip]') == '10.0.0.5' &&
      ok.get('[soc][fw][session][id]') == 'admin|FG1|1793' && ok.get('[soc][fw][session][state]') == 'open' && ok.get('[event][outcome]') == 'success' &&
      bad.get('[soc][fw][access][outcome]') == 'failure' && bad.get('[soc][fw][session][id]').nil? && bad.get('[source][ip]') == '203.0.113.9' &&
      bad.get('[soc][fw][access][user]') == 'root' && out.get('[soc][fw][session][state]') == 'close' && out.get('[soc][fw][session][id]') == 'admin|FG1|1793'
  end
end

test 'VPN SSL e IPsec: túnel abre e fecha pelo tunnelid; falha de login não vira sessão' do
  in_event do
    base = 'date=2026-10-27 time=11:00:00 tz="-0300" type="event" subtype="vpn" devid="FG1" '
    [{ 'message' => base + 'action="tunnel-up" tunneltype="ssl-tunnel" tunnelid=77 remip=198.51.100.7 tunnelip=10.212.134.200 user="maria"' },
     { 'message' => base + 'action="tunnel-down" tunneltype="ssl-tunnel" tunnelid=77 remip=198.51.100.7 user="maria" duration=3600 sentbyte=10 rcvdbyte=20' },
     { 'message' => base + 'action="ssl-login-fail" tunneltype="ssl-web" remip=198.51.100.8 user="joao" reason="sslvpn_login_permission_denied"' },
     { 'message' => base + 'action="tunnel-up" tunneltype="ipsec" vpntunnel="FILIAL" remip=198.51.100.9 xauthuser="pedro"' }]
  end
  expect('estado, tipo e usuário') do |events|
    up, down, fail, ipsec = events
    up.get('[soc][fw][session][id]') == 'vpn|FG1|77' && up.get('[soc][fw][session][state]') == 'open' && up.get('[soc][fw][access][channel]') == 'ssl' &&
      up.get('[fortinet][firewall][tunnelip]') == '10.212.134.200' && up.get('[soc][fw][access][outcome]') == 'success' &&
      down.get('[soc][fw][session][state]') == 'close' && down.get('[event][duration]') == 3_600_000_000_000 &&
      fail.get('[soc][fw][access][outcome]') == 'failure' && fail.get('[soc][fw][session][id]').nil? && fail.get('[source][ip]') == '198.51.100.8' &&
      ipsec.get('[soc][fw][access][channel]') == 'ipsec' && ipsec.get('[soc][fw][access][user]') == 'pedro' &&
      ipsec.get('[soc][fw][session][id]') == 'vpn|FG1|FILIAL|198.51.100.9'
  end
end
