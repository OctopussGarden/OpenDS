#!/usr/bin/python3 -I
"""Root-owned OpenDS USB/IP helper: loopback Sony exports owned by its caller."""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

RUNTIME=Path('/run/opends-usbip')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


def number(text,low,high):
    if not re.fullmatch(r'[0-9]{1,10}',text):raise ValueError('Invalid numeric argument')
    value=int(text)
    if not low<=value<=high:raise ValueError('Argument outside allowed range')
    return value


def trusted(path):
    path=Path(path).resolve(strict=True)
    if not path.is_file():raise ValueError('USB/IP executable is not a file')
    for item in [path,*path.parents]:
        info=item.stat()
        if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe USB/IP executable path')
    return path


def executable():
    for path in [Path('/usr/lib/linux-tools')/os.uname().release/'usbip',Path('/usr/sbin/usbip'),Path('/usr/bin/usbip')]:
        if path.exists():return trusted(path)
    raise ValueError('Install the kernel-matching linux-tools package')


def command(exe,*args):
    result=subprocess.run([str(exe),*args],env=ENV,capture_output=True,text=True,timeout=12)
    if result.returncode:raise ValueError(result.stderr.strip() or result.stdout.strip() or 'USB/IP failed')
    return result.stdout


def owned_listener(uid,port,table=None):
    table=Path('/proc/net/tcp').read_text() if table is None else table
    endpoint=f'0100007F:{port:04X}'
    return any(len(fields)>7 and fields[1]==endpoint and fields[3]=='0A' and fields[7]==str(uid)
               for fields in (line.split() for line in table.splitlines()[1:]))


def entries(text):
    result={};port=None;sony=False;lines=[]
    for line in text.splitlines():
        match=re.match(r'\s*Port (\d+):',line)
        if match:port=int(match[1]);sony=False;lines=[line]
        elif port is not None:
            lines.append(line)
            if re.search(r'\(054c:(?:0ce6|0df2)\)',line,re.I):sony=True
            match=re.search(r'-> usbip://(?:127\.0\.0\.1|localhost):(\d+)/(\d+)-1\s*$',line)
            if sony and match:result[port]=(int(match[1]),int(match[2]),'\n'.join(lines)+'\n')
    return result


def valid_export(text,bus):
    return re.search(r'^[ \t]*(?:-[ \t]+)?'+str(bus)+r'-1:[ \t]*[^\n]*\(054c:(?:0ce6|0df2)\)',text,re.I|re.M) is not None


def records(uid):
    for path in RUNTIME.glob(f'{uid}-*.json'):
        data=json.loads(path.read_text())
        if data['uid']==uid:yield path,data


def operate(uid,operation,args,exe):
    listing=entries(command(exe,'port'))
    if operation=='port':
        if args:raise ValueError('port takes no arguments')
        output=['Imported OpenDS USB devices\n==========================\n']
        for path,data in list(records(uid)):
            current=listing.get(data['vhci'])
            if current and current[:2]==(data['tcp'],data['bus']):output.append(current[2])
            else:path.unlink()
        return '\n'.join(output)
    if operation=='attach':
        if len(args)!=2:raise ValueError('attach requires TCP port and bus number')
        tcp=number(args[0],1024,65535);bus=number(args[1],1,0xffffffff)
        if not owned_listener(uid,tcp):raise ValueError('The loopback server must belong to the caller')
        if not valid_export(command(exe,'--tcp-port',str(tcp),'list','-r','127.0.0.1'),bus):
            raise ValueError('Only a local DualSense or DualSense Edge export is allowed')
        # Never adopt another caller's already attached VHCI port.
        matches=[port for port,item in listing.items() if item[:2]==(tcp,bus)]
        for path,data in records(uid):
            if data['vhci'] in matches and data['tcp']==tcp and data['bus']==bus:return ''
        if matches:raise ValueError('The export is already attached without caller ownership')
        command(exe,'--tcp-port',str(tcp),'attach','-r','127.0.0.1','-b',f'{bus}-1')
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            current=entries(command(exe,'port'))
            matches=[port for port,item in current.items() if item[:2]==(tcp,bus)]
            if matches:
                data={'uid':uid,'tcp':tcp,'bus':bus,'vhci':matches[0]}
                path=RUNTIME/f'{uid}-{matches[0]}.json'
                path.write_text(json.dumps(data)+'\n');path.chmod(0o600)
                return ''
            time.sleep(.05)
        raise ValueError('USB/IP attachment did not appear; stop the bridge to close the connection')
    if operation=='detach':
        if len(args)!=1:raise ValueError('detach requires one VHCI port')
        port=number(args[0],0,65535);path=RUNTIME/f'{uid}-{port}.json'
        if not path.is_file():raise ValueError('The caller does not own this bridge port')
        data=json.loads(path.read_text());current=listing.get(port)
        if current:
            if data['uid']!=uid or current[:2]!=(data['tcp'],data['bus']):raise ValueError('VHCI port ownership changed')
            command(exe,'detach','-p',str(port))
        elif re.search(r'^\s*Port\s+0*'+str(port)+r':',command(exe,'port'),re.M):
            raise ValueError('Refusing to detach an unrelated device')
        path.unlink();return ''
    raise ValueError('Only attach, detach and port are supported')


def main():
    if os.geteuid()!=0:raise ValueError('Use the installed OpenDS policy helper')
    uid=number(os.environ.get('PKEXEC_UID','0'),0,0xffffffff)
    if len(sys.argv)<2:raise ValueError('Missing operation')
    RUNTIME.mkdir(mode=0o700,exist_ok=True)
    info=RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise ValueError('Unsafe runtime directory')
    with (RUNTIME/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        print(operate(uid,sys.argv[1],sys.argv[2:],executable()),end='')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.TimeoutExpired) as error:
        print('OpenDS USB/IP: '+str(error),file=sys.stderr);sys.exit(1)
