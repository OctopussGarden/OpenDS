#!/usr/bin/python3
"""Install the narrow OpenDS policy/helper once; daily bridge operations need no password."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import sys

POLICY='''<?xml version="1.0" encoding="UTF-8"?>
<policyconfig>
 <vendor>OpenDS</vendor>
 <action id="io.github.OpenDS.bridge">
  <description>Manage the current user's local OpenDS bridge</description>
  <message>Authentication is required to set up the OpenDS bridge</message>
  <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin_keep</allow_active></defaults>
  <annotate key="org.freedesktop.policykit.exec.path">/usr/local/libexec/opends-usbip</annotate>
 </action>
</policyconfig>
'''


def install(prefix,user):
    here=Path(__file__).resolve().parent
    source=here.parent/'src/linux/opends_usbip_helper.py'
    if not source.is_file():source=here/'opends-usbip-helper.py'
    if not source.is_file():raise SystemExit('The OpenDS USB/IP helper source is missing')
    targets={
      'usr/local/libexec/opends-usbip':source.read_text(),
      'usr/share/polkit-1/actions/io.github.OpenDS.bridge.policy':POLICY,
      'etc/polkit-1/rules.d/49-opends-bridge.rules':
        'polkit.addRule(function(action, subject) {\n'
        '  if (action.id === "io.github.OpenDS.bridge" && subject.user === '+json.dumps(user)+' && subject.local && subject.active)\n'
        '    return polkit.Result.YES;\n});\n',
    }
    for name,content in targets.items():
        target=prefix/name;target.parent.mkdir(parents=True,exist_ok=True)
        temporary=target.with_name(target.name+'.installing')
        temporary.write_text(content,encoding='utf-8');temporary.chmod(0o755 if name.endswith('/opends-usbip') else 0o644)
        temporary.replace(target)
    print('Installed OpenDS bridge policy for '+user+'. Start/stop uses no password in your active local session.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,default=Path('/'),help='Staging prefix for validation')
    parser.add_argument('--user',help='Desktop user; defaults to the authenticated setup caller')
    args=parser.parse_args()
    if args.prefix==Path('/') and os.geteuid()!=0:
        os.execv('/usr/bin/pkexec',['pkexec','/usr/bin/python3','-I',str(Path(__file__).resolve()),*sys.argv[1:]])
    user=args.user or pwd.getpwuid(int(os.environ.get('PKEXEC_UID',os.environ.get('SUDO_UID',str(os.getuid()))))).pw_name
    pwd.getpwnam(user)
    install(args.prefix,user)
