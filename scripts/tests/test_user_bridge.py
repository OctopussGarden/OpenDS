"""Validate the bridge helper without root, USB/IP attachment, or policy changes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bridge_helper',ROOT/'src/linux/opends_usbip_helper.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
LISTING='Port 00: <Port in Use> at High Speed(480Mbps)\n Sony (054c:0ce6)\n 8-1 -> usbip://127.0.0.1:3242/1-1\n'


class UserBridge(unittest.TestCase):
 def test_numeric_arguments_cannot_inject_options_or_paths(self):
  for value in ['-1','--help','1;id','../1','1 2','4294967296']:
   with self.subTest(value=value),self.assertRaises(ValueError):helper.number(value,0,0xffffffff)
  self.assertEqual(helper.number('0',0,65535),0)
 def test_only_the_callers_ipv4_loopback_listener_is_allowed(self):
  table='header\n0: 0100007F:0CAA 00000000:0000 0A 0:0 00:0 0 1000 0 123\n'
  self.assertTrue(helper.owned_listener(1000,3242,table))
  self.assertFalse(helper.owned_listener(1001,3242,table))
  self.assertFalse(helper.owned_listener(1000,3243,table))
  self.assertFalse(helper.owned_listener(1000,3242,table.replace('0100007F','00000000')))
 def test_only_exact_sony_export_and_loopback_port_are_matched(self):
  self.assertTrue(helper.valid_export(' - 1-1: Sony : DualSense (054c:0ce6)',1))
  self.assertFalse(helper.valid_export(' - 1-10: Sony (054c:0ce6)',1))
  self.assertFalse(helper.valid_export(' - 1-1: Other (1234:5678)',1))
  self.assertEqual(helper.entries(LISTING)[0][:2],(3242,1))
  self.assertEqual(helper.entries(LISTING.replace('127.0.0.1','remote')), {})
 def test_cannot_detach_other_users_or_reassigned_ports(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(helper,'RUNTIME',Path(directory)):
   with patch.object(helper,'command',return_value=LISTING) as command:
    with self.assertRaises(ValueError):helper.operate(1001,'detach',['0'],'usbip')
    self.assertEqual(command.call_count,1)
   path=Path(directory)/'1000-0.json';path.write_text(json.dumps({'uid':1000,'tcp':3241,'bus':1,'vhci':0}))
   with patch.object(helper,'command',return_value=LISTING) as command:
    with self.assertRaises(ValueError):helper.operate(1000,'detach',['0'],'usbip')
    self.assertEqual(command.call_count,1)
 def test_attach_records_ownership_and_detach_is_scoped(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(helper,'RUNTIME',Path(directory)):
   outputs=['Imported USB devices\n',' - 1-1: Sony (054c:0ce6)\n','',LISTING]
   with patch.object(helper,'owned_listener',return_value=True),patch.object(helper,'command',side_effect=outputs) as command:
    helper.operate(1000,'attach',['3242','1'],'usbip')
    self.assertEqual(command.call_args_list[2].args,('usbip','--tcp-port','3242','attach','-r','127.0.0.1','-b','1-1'))
   path=Path(directory)/'1000-0.json';self.assertTrue(path.is_file())
   self.assertEqual(path.stat().st_mode&0o777,0o600)
   with patch.object(helper,'command',side_effect=[LISTING,'']) as command:
    helper.operate(1000,'detach',['0'],'usbip')
    self.assertEqual(command.call_args.args,('usbip','detach','-p','0'))
   self.assertFalse(path.exists())
 def test_installer_stages_a_dedicated_action_without_generic_sudo_rules(self):
  import pwd,os
  with tempfile.TemporaryDirectory() as directory:
   subprocess.run(['/usr/bin/python3',str(ROOT/'scripts/setup-user-bridge.py'),'--prefix',directory,'--user',pwd.getpwuid(os.getuid()).pw_name],check=True,capture_output=True)
   root=Path(directory)
   action=ET.parse(root/'usr/share/polkit-1/actions/io.github.OpenDS.bridge.policy').find('action')
   self.assertEqual(action.attrib['id'],'io.github.OpenDS.bridge')
   self.assertEqual(action.find('annotate').text,'/usr/local/libexec/opends-usbip')
   rule=(root/'etc/polkit-1/rules.d/49-opends-bridge.rules').read_text()
   self.assertIn('subject.local && subject.active',rule)
   self.assertFalse((root/'etc/sudoers.d').exists())


if __name__=='__main__':unittest.main()
