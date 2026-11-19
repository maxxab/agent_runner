"""Fixed read-only request grammar and safe projections; no daemon calls."""
import json
import unittest
from automation import control_docker_http as http
from tests.test_automation_docker_http import response, drain


class DiscoveryTests(unittest.TestCase):
    def values(self):
        return ({'Version':'29.1.3','ApiVersion':'1.52','MinAPIVersion':'1.44','Os':'linux','Arch':'amd64',
                 'Components':[{'Details':{'secret':'must not escape'}}]},
                {'CgroupDriver':'systemd','CgroupVersion':'2','Name':'private-host','DockerRootDir':'/private'})

    def test_only_empty_identifier_and_body_allow_fixed_read_routes(self):
        for op in ('version','info'):
            self.assertTrue(http.Request(op,'').encode().startswith(('GET /v1.51/'+op+' HTTP/1.1\r\n').encode()))
            for ident,body in (('a'*64,b''),('',b'{}'),('../info',b'')):
                with self.assertRaises(ValueError):http.Request(op,ident,body).encode()

    def test_finite_json_response_for_discovery(self):
        for op in ('version','info'):
            parser=http.Response(http.Request(op,''))
            parser.feed(response(b'{"ok":true}'));drain(parser)
            self.assertEqual(parser.value(),{'ok':True});parser.finish()

    def test_safe_projection_drops_all_unneeded_values(self):
        version,info=self.values()
        self.assertEqual(http.discovery_projection(version,info),dict(
            engine_version='29.1.3',api_min='1.44',api_max='1.52',api_selected='1.51',
            os='linux',architecture='amd64',cgroup_driver='systemd',cgroup_version='2'))
        info['CgroupDriver']='cgroupfs'
        self.assertEqual(http.discovery_projection(version,info)['cgroup_driver'],'cgroupfs')
        self.assertNotIn('private',json.dumps(http.discovery_projection(version,info)))

    def test_missing_wrong_type_unsupported_or_unbounded_values_reject(self):
        version,info=self.values()
        for key,bad in [('Version','arbitrary private message'),('Version',True),('ApiVersion','1.50'),
                        ('MinAPIVersion','1.52'),('ApiVersion','99.'+'1'*200),('Os','windows'),('Arch','arm64')]:
            with self.subTest(key=key,bad=bad),self.assertRaises(ValueError):
                http.discovery_projection(version|{key:bad},info)
        for key,bad in [('CgroupDriver','unknown'),('CgroupVersion','1'),('CgroupVersion',2)]:
            with self.subTest(key=key),self.assertRaises(ValueError):http.discovery_projection(version,info|{key:bad})
        for key in version.keys()-{'Components'}:
            changed=dict(version);changed.pop(key)
            with self.assertRaises(ValueError):http.discovery_projection(changed,info)

if __name__=='__main__':unittest.main()
