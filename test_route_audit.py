import copy
import unittest
from GuardRouteAudit import audit_model, AuditFailure, DOMAINS, domain_matches

class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.config={'mode':'rule','ipv6':False,'proxies':[{'name':'pinned','type':'anytls'}],
                     'proxy-groups':[{'name':'CrossGo','type':'select','proxies':['pinned']}],
                     'rules':['RULE-SET,protected,CrossGo','MATCH,DIRECT']}
        self.providers={'protected':('domain',['+.'+d for d in DOMAINS])}
    def reject(self):
        with self.assertRaises(AuditFailure): audit_model(self.config,self.providers,{'claude.exe'})
    def test_all_protected_domains_route_before_direct(self):
        routes,count=audit_model(self.config,self.providers,{'claude.exe'})
        self.assertEqual(len(routes),len(DOMAINS));self.assertEqual(count,2)
    def test_earlier_direct_rule_blocks_launch(self):
        self.config['rules'].insert(0,'DOMAIN-SUFFIX,anthropic.com,DIRECT');self.reject()
    def test_process_direct_override_blocks_launch(self):
        self.config['rules'].insert(0,'PROCESS-NAME,claude.exe,DIRECT');self.reject()
    def test_direct_candidate_in_group_blocks_launch(self):
        self.config['proxy-groups'][0]['proxies'].append('DIRECT');self.reject()
    def test_nested_direct_candidate_blocks_launch(self):
        self.config['proxy-groups'][0]['proxies']=['nested']
        self.config['proxy-groups'].append({'name':'nested','type':'fallback','proxies':['pinned','DIRECT']});self.reject()
    def test_cycles_block_launch(self):
        self.config['proxy-groups'][0]['proxies']=['CrossGo'];self.reject()
    def test_missing_provider_blocks_launch(self):
        self.providers={};self.reject()
    def test_dynamic_candidates_block_launch(self):
        self.config['proxy-groups'][0]['include-all']=True;self.reject()
    def test_unresolved_ip_rule_before_domain_blocks_launch(self):
        self.config['rules'].insert(0,'GEOIP,CN,DIRECT');self.reject()
    def test_unreviewed_proxy_type_blocks_launch(self):
        self.config['proxies'][0]['type']='direct';self.reject()
    def test_direct_mode_blocks_launch(self):
        self.config['mode']='direct';self.reject()
    def test_ipv6_blocks_launch(self):
        self.config['ipv6']=True;self.reject()
    def test_domain_boundary_is_not_substring(self):
        self.assertTrue(domain_matches('+.claude.ai','api.claude.ai'))
        self.assertFalse(domain_matches('+.claude.ai','evilclaude.ai'))
        self.assertFalse(domain_matches('+.claude.ai','claude.ai.example.com'))

    def test_selected_domains_and_custom_group(self):
        self.config['proxy-groups'][0]['name']='UserSelected'
        self.config['rules']=['DOMAIN-SUFFIX,chatgpt.com,UserSelected','MATCH,DIRECT']
        routes,count=audit_model(self.config,{}, {'codex.exe'},target='UserSelected',domains=['chatgpt.com'])
        self.assertEqual(len(routes),1)
        self.assertEqual(count,2)
    def test_selected_codex_domain_cannot_fall_back_to_direct(self):
        self.config['proxy-groups'][0]['name']='UserSelected'
        self.config['rules']=['DOMAIN-SUFFIX,chatgpt.com,UserSelected','MATCH,DIRECT']
        with self.assertRaises(AuditFailure):
            audit_model(self.config,{}, {'codex.exe'},target='UserSelected',domains=['chatgpt.com','api.openai.com'])
    def test_unselected_client_domains_do_not_force_registration(self):
        self.config['rules']=['DOMAIN,claude.ai,CrossGo','MATCH,DIRECT']
        routes,count=audit_model(self.config,{}, {'claude.exe'},domains=['claude.ai'])
        self.assertEqual(len(routes),1)
if __name__=='__main__': unittest.main(verbosity=2)