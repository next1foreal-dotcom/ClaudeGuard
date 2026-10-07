"""Read-only FlClash routing audit. Never prints node credentials or subscription URLs."""
import fnmatch
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
import yaml

DOMAINS = ['claude.ai', 'api.anthropic.com', 'auth.anthropic.com', 'claude.com',
           'claudeusercontent.com', 'claudemcpclient.com', 'claudemcpcontent.com']

class AuditFailure(Exception):
    pass

def domain_matches(pattern, host):
    pattern = pattern.lower().rstrip('.')
    host = host.lower().rstrip('.')
    if pattern.startswith('+.'):
        suffix = pattern[2:]
        return host == suffix or host.endswith('.' + suffix)
    if pattern.startswith('.'):
        return host.endswith(pattern)
    return fnmatch.fnmatchcase(host, pattern) if '*' in pattern else host == pattern

def require_proxy_graph(config, group):
    groups = {p['name']: p for p in config.get('proxy-groups', [])}
    proxies = {p['name']: p for p in config.get('proxies', [])}
    reached = set()
    def visit(name, active):
        if name.upper() in ('DIRECT', 'PASS', 'COMPATIBLE'):
            raise AuditFailure('Proxy chain contains a direct/pass candidate.')
        if name in active:
            raise AuditFailure('Proxy chain contains a cycle.')
        if name in reached:
            return
        if name in groups:
            item = groups[name]
            if item.get('use') or any(item.get(k) for k in ('include-all', 'include-all-proxies', 'include-all-providers')):
                raise AuditFailure('Dynamic provider expansion is not covered by this audit.')
            if not item.get('proxies'):
                raise AuditFailure('Proxy group has no explicit members.')
            for child in item['proxies']:
                visit(child, active | {name})
        elif name in proxies:
            item = proxies[name]
            if item.get('type', '').lower() not in ('anytls', 'ss', 'ssr', 'trojan', 'vmess', 'vless', 'hysteria', 'hysteria2', 'tuic', 'socks5', 'http'):
                raise AuditFailure('Unreviewed outbound proxy type.')
            if item.get('dialer-proxy'):
                visit(item['dialer-proxy'], active | {name})
        else:
            raise AuditFailure('Proxy group references an unresolved member.')
        reached.add(name)
    visit(group, set())
    return len(reached)

def audit_model(config, providers, process_names, target='CrossGo'):
    if config.get('mode') != 'rule' or config.get('ipv6') is not False:
        raise AuditFailure('Expected rule mode with IPv6 disabled.')
    graph_count = require_proxy_graph(config, target)
    def match_classical(rule, host):
        parts = rule.split(',')
        kind = parts[0].upper()
        value = parts[1] if len(parts) > 1 else ''
        if kind == 'DOMAIN':
            return host == value.lower()
        if kind == 'DOMAIN-SUFFIX':
            return host == value.lower() or host.endswith('.' + value.lower())
        if kind == 'DOMAIN-KEYWORD':
            return value.lower() in host
        if kind == 'PROCESS-NAME':
            return value.lower() in process_names
        if kind == 'PROCESS-PATH':
            return Path(value).name.lower() in process_names
        if kind == 'MATCH':
            return True
        raise AuditFailure('Cannot safely evaluate preceding rule type: ' + kind)
    routes = []
    for host in DOMAINS:
        found = False
        for rule in config.get('rules', []):
            parts = rule.split(',')
            if len(parts) < 2:
                raise AuditFailure('Malformed rule.')
            kind = parts[0].upper()
            if kind == 'RULE-SET':
                provider = providers.get(parts[1])
                if provider is None:
                    raise AuditFailure('Rule provider is unavailable.')
                behavior, payload = provider
                if behavior == 'domain':
                    hit = any(domain_matches(x, host) for x in payload)
                elif behavior == 'classical':
                    hit = any(match_classical(x, host) for x in payload)
                else:
                    raise AuditFailure('An IP-based rule precedes the domain proxy decision.')
                destination = parts[2]
            else:
                hit = match_classical(','.join(parts[:2]), host)
                destination = parts[1] if kind == 'MATCH' else parts[2]
            if hit:
                if destination != target:
                    raise AuditFailure('Protected domain matches a non-approved route: ' + host)
                routes.append({'domain': host, 'route': destination, 'rule': ','.join(parts[:2])})
                found = True
                break
        if not found:
            raise AuditFailure('Protected domain has no confirmed proxy rule.')
    return routes, graph_count

def audit(root, guard_config):
    config_path = root / 'config.yaml'
    config_bytes = config_path.read_bytes()
    config = yaml.safe_load(config_bytes)
    prefs = json.loads(json.loads((root / 'shared_preferences.json').read_text(encoding='utf-8'))['flutter.config'])
    if prefs['patchClashConfig'].get('mode') != 'rule':
        raise AuditFailure('Saved FlClash mode is not rule mode.')
    profile_id = prefs['currentProfileId']
    with sqlite3.connect((root / 'database.sqlite').as_uri() + '?mode=ro', uri=True) as db:
        row = db.execute('select selected_map from profiles where id=?', (profile_id,)).fetchone()
    if not row:
        raise AuditFailure('Active profile selection is missing.')
    selected = json.loads(row[0]).get('CrossGo')
    nodes = {p['name']: p for p in config.get('proxies', [])}
    if selected not in nodes:
        raise AuditFailure('CrossGo must select a specific proxy node, not an automatic group.')
    fingerprint = hashlib.sha256(json.dumps(nodes[selected], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    expected = guard_config.get('RoutingPin', {})
    if expected and (str(profile_id) != str(expected.get('ProfileId')) or fingerprint != expected.get('SelectedNodeSHA256')):
        raise AuditFailure('Selected profile or node differs from the approved routing pin.')
    providers = {}
    provider_hashes = {}
    for name, item in config.get('rule-providers', {}).items():
        path = Path(item['path'])
        if not path.is_absolute():
            path = root / path
        data = path.read_bytes()
        providers[name] = (item['behavior'], yaml.safe_load(data).get('payload', []))
        provider_hashes[name] = hashlib.sha256(data).hexdigest()
    names = {Path(p).name.lower() for p in guard_config['ProtectedPrograms']}
    routes, graph_count = audit_model(config, providers, names)
    if config_path.read_bytes() != config_bytes:
        raise AuditFailure('FlClash configuration changed during the audit.')
    return {'ok': True, 'profileId': str(profile_id), 'selectedNode': selected,
            'selectedNodeSHA256': fingerprint, 'routes': routes, 'graphMembers': graph_count,
            'configSHA256': hashlib.sha256(config_bytes).hexdigest(), 'providerHashes': provider_hashes,
            'evidenceScope': 'Saved selection and generated configuration; not a live control-API response.'}

if __name__ == '__main__':
    try:
        guard = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
        result = audit(Path(guard['FlClashDirectory']), guard)
        print(json.dumps(result, ensure_ascii=True))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=True))
        sys.exit(1)