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
