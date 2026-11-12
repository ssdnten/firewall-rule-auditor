import unittest
from main import audit

def rule(ident='a',source='0.0.0.0/0',ports=None,action='allow',protocol='tcp'):
    return dict(id=ident,source=source,ports=ports if ports is not None else [22],action=action,protocol=protocol)

class Tests(unittest.TestCase):
    def test_public_admin(self): self.assertEqual(audit([rule()])[0]['kind'],'internet_admin_exposure')
    def test_ipv6(self): self.assertEqual(audit([rule(source='::/0')])[0]['ports'],[22])
    def test_private(self): self.assertEqual(audit([rule(source='10.0.0.0/8')]),[])
    def test_shadowed(self): self.assertIn(dict(rule='b',kind='shadowed',by='a'),audit([rule(action='deny'),rule('b',source='192.0.2.0/24')]))
    def test_partial_overlap_not_shadowed(self): self.assertFalse(any(x['kind']=='shadowed' for x in audit([rule(ports=[22]),rule('b',ports=[22,443])])))
    def test_protocol_separation(self): self.assertFalse(any(x['kind']=='shadowed' for x in audit([rule(),rule('b',protocol='udp')])))
    def test_invalid_port(self):
        with self.assertRaises(ValueError): audit([rule(ports=[True])])
