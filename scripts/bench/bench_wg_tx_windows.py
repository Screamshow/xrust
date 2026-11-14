#!/usr/bin/env python3
"""Owned Linux/WSL AWG A/B fixture. Root and eight available CPUs required.

Only a dedicated netns/veth is changed; no router or host networking mode changes.
"""
# SPDX-License-Identifier: GPL-3.0-only
import argparse, asyncio, collections, hashlib, ipaddress, json, os, signal, socket
import statistics, struct, subprocess, sys, tempfile, time, shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parent
NS='awg-adaptive14';VETH='awgad14';PEER='awgpd14';AWG='awgadwg14'
OUTER_LOCAL='10.216.114.1';OUTER_PEER='10.216.114.2';INNER='10.216.115.1';CLIENT='10.216.115.2'
PORT=21947;SOCKS=45822;SINK=45821
PROFILE={'jc':4,'jmin':40,'jmax':70,'s1':16,'s2':24,'s3':16,'s4':16,
         'h1':11010101,'h2':22020202,'h3':33030303,'h4':44040404}
BLOCK=16384

def command(args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,**kwargs).stdout
def ns(*args,**kwargs):return command(['ip','netns','exec',NS,*map(str,args)],**kwargs)
def save(path,data):
    tmp=path.with_suffix(path.suffix+'.tmp');tmp.write_text(json.dumps(data,indent=2));tmp.replace(path)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def network_mode():
    return command(['wslinfo','--networking-mode'],text=True).strip() if shutil.which('wslinfo') else 'linux'
def terminate(p):
    if p is not None and p.poll() is None:
        os.killpg(p.pid,signal.SIGTERM)
        try:p.wait(5)
        except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(3)
def affinity(cpus):
    def set_affinity():os.sched_setaffinity(0,set(cpus))
    return set_affinity
def spawn(args,log,cpus,env=None):
    return subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log,
        env=env,preexec_fn=affinity(cpus),start_new_session=True)
def proc_stats(pid):
    stat=Path(f'/proc/{pid}/stat').read_text().split();status=Path(f'/proc/{pid}/status').read_text()
    inodes=set()
    for f in Path(f'/proc/{pid}/fd').iterdir():
        try:link=f.readlink().as_posix()
        except (FileNotFoundError,PermissionError):continue
        if link.startswith('socket:['):inodes.add(link[8:-1])
    drops=0;queues=[]
    for proto in ['udp','udp6']:
        for line in Path(f'/proc/{pid}/net/'+proto).read_text().splitlines()[1:]:
            f=line.split()
            if f[9] in inodes:drops+=int(f[-1]);queues.append(f[4])
    memory={l.split(':')[0]:int(l.split()[1]) for l in status.splitlines() if l.startswith(('VmRSS:','VmHWM:','RssAnon:'))}
    return dict(t=time.perf_counter(),cpu_s=(int(stat[13])+int(stat[14]))/os.sysconf('SC_CLK_TCK'),memory_kib=memory,
                drops=drops,queues=queues,fds=len(list(Path(f'/proc/{pid}/fd').iterdir())))

async def paced_send(w,n,rate,byte):
    sent=0;start=time.perf_counter();chunk=bytes([byte])*BLOCK
    while sent<n:
        if rate:
            wait=start+sent*8/rate-time.perf_counter()
            if wait>0:await asyncio.sleep(wait)
        data=chunk[:min(BLOCK,n-sent)];w.write(data);await w.drain();sent+=len(data)
async def receive(r,n,byte):
    got=0
    while got<n:
        data=await r.read(min(65536,n-got));assert data and data.count(byte)==len(data),'payload mismatch'
        got+=len(data)
async def handler(r,w):
    try:
        h=await r.readexactly(9);kind=h[:1];n=int.from_bytes(h[1:5],'big');rate=int.from_bytes(h[5:9],'big')
        w.write(b'R');await w.drain()
        if kind==b'E':
            while True:
                data=await r.readexactly(64);w.write(data);await w.drain()
        elif kind==b'D':
            assert await r.readexactly(1)==b'G';await paced_send(w,n,rate,122)
        elif kind==b'U':
            assert await r.readexactly(1)==b'G';await receive(r,n,120)
        else:raise AssertionError('invalid operation')
        w.write(b'A');await w.drain()
    except (asyncio.IncompleteReadError,ConnectionError):pass
    finally:w.close()
async def serve(ready):
    srv=await asyncio.start_server(handler,INNER,SINK);Path(ready).touch()
    async with srv:await srv.serve_forever()
async def socks():
    r,w=await asyncio.open_connection('127.0.0.1',SOCKS)
    w.write(b'\5\1\0');await w.drain();assert await r.readexactly(2)==b'\5\0'
    w.write(b'\5\1\0\1'+ipaddress.IPv4Address(INNER).packed+SINK.to_bytes(2,'big'));await w.drain()
    h=await r.readexactly(4);assert h[1]==0,h;await r.readexactly(6 if h[3]==1 else 18)
    return r,w
async def echo_open():
    r,w=await socks();w.write(b'E'+bytes(8));await w.drain();assert await r.readexactly(1)==b'R'
    w.write(bytes(64));await w.drain();assert await r.readexactly(64)==bytes(64)
    return r,w
async def close_all(items):
    for _,w in items:w.close()
    for _,w in items:
        try:await w.wait_closed()
        except ConnectionError:pass
async def transfer(direction,n,rate,barrier):
    r,w=await socks()
    w.write((b'D' if direction=='down' else b'U')+n.to_bytes(4,'big')+rate.to_bytes(4,'big'));await w.drain()
    assert await r.readexactly(1)==b'R';await barrier.wait();start=time.perf_counter();w.write(b'G');await w.drain()
    try:
        if direction=='down':await receive(r,n,122)
        else:await paced_send(w,n,rate,120)
        assert await r.readexactly(1)==b'A';end=time.perf_counter()
        return dict(bytes=n,start=start,end=end,seconds=end-start,mbit_s=n*8/(end-start)/1e6)
    finally:w.close();await w.wait_closed()

async def batch(req,pid):
    held=[];echo_ms=[];echo_errors=[];samples=[];task=None;echo_task=None;lease_observations={}
    try:
        for _ in range(req['held']):held.append(await echo_open())
        if req.get('prime_held_bytes'):
            n=req['prime_held_bytes'];data=bytes([37])*n
            for r,w in held:
                w.write(data);await w.drain();assert await r.readexactly(n)==data
            lease_observations['after_priming']=proc_stats(pid)
        if req.get('settle_seconds'):
            await asyncio.sleep(req['settle_seconds']);lease_observations['after_idle']=proc_stats(pid)
        er,ew=await echo_open()
        async def echo():
            try:
                while True:
                    t=time.perf_counter();ew.write(bytes(64));await ew.drain();assert await er.readexactly(64)==bytes(64)
                    echo_ms.append((time.perf_counter()-t)*1000);await asyncio.sleep(.1)
            except Exception as e:echo_errors.append(type(e).__name__)
        async def monitor():
            while True:samples.append(proc_stats(pid));await asyncio.sleep(.1)
        echo_task=asyncio.create_task(echo());task=asyncio.create_task(monitor())
        await asyncio.sleep(.12);before=proc_stats(pid);wall=time.perf_counter()
        barrier=asyncio.Barrier(req['flows'])
        values=await asyncio.wait_for(asyncio.gather(*(transfer(req['direction'],req['bytes_per_flow'],req['rate_per_flow'],barrier) for _ in range(req['flows']))),req['timeout'])
        after=proc_stats(pid);assert not echo_errors,echo_errors
        payload=sum(x['bytes'] for x in values);duration=max(x['end'] for x in values)-min(x['start'] for x in values)
        cpu=after['cpu_s']-before['cpu_s'];assert echo_ms
        if req.get('prime_held_bytes'):
            n=req['prime_held_bytes'];data=bytes([51])*n;regrowth_start=time.perf_counter()
            for r,w in held:
                w.write(data);await w.drain();assert await r.readexactly(n)==data
            lease_observations['same_connections_reused']=True
            lease_observations['regrowth_echo_bytes']=n*len(held)
            lease_observations['regrowth_seconds']=time.perf_counter()-regrowth_start
            lease_observations['after_regrowth']=proc_stats(pid)
        return dict(status='OK',transfers=values,payload=payload,data_seconds=duration,mbit_s=payload*8/duration/1e6,
                    wall_seconds=time.perf_counter()-wall,cpu_s=cpu,cpu_pct=100*cpu/(after['t']-before['t']),
                    cpu_s_gib=cpu*2**30/payload,rss_peak_kib=max(s['memory_kib']['VmRSS'] for s in samples),
                    rss_before_kib=before['memory_kib']['VmRSS'],rss_after_kib=after['memory_kib']['VmRSS'],
                    drops=after['drops']-before['drops'],fds_before=before['fds'],fds_after=after['fds'],
                    echo_ms=echo_ms,echo_median_ms=statistics.median(echo_ms),before=before,after=after,samples=samples,
                    lease_observations=lease_observations)
    finally:
        for t in [task,echo_task]:
            if t:t.cancel()
        await asyncio.gather(*(t for t in [task,echo_task] if t),return_exceptions=True)
        if 'ew' in locals():ew.close();await ew.wait_closed()
        await close_all(held)

def capture(output,stopfile):
    os.sched_setaffinity(0,{7});counts=collections.Counter();sizes=collections.Counter();types=collections.Counter();prefixes=set();total=0
    running=True
    def stop(*_):nonlocal running;running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(3)) as s:
        s.bind((VETH,0));s.settimeout(.1);start=time.monotonic();Path(output+'.ready').touch()
        while running and time.monotonic()-start<1200 and total<250000 and not Path(stopfile).exists():
            try:p=s.recv(256)
            except TimeoutError:continue
            if len(p)<28 or p[0]>>4!=4 or p[9]!=17:continue
            h=(p[0]&15)*4
            if len(p)<h+8:continue
            sport,dport,ulen,_=struct.unpack('!HHHH',p[h:h+8])
            if PORT not in [sport,dport]:continue
            data=p[h+8:];direction='client_to_peer' if dport==PORT else 'peer_to_client';length=ulen-8
            kind='junk_or_other'
            for k in ['h1','h2','h3','h4']:
                off=PROFILE['s'+k[1:]]
                if len(data)>=off+4 and struct.unpack('<I',data[off:off+4])[0]==PROFILE[k]:kind=k;break
            counts[direction]+=1;sizes[str(length)]+=1;types[direction+':'+kind]+=1;total+=1
            if kind=='h4':prefixes.add(data[:16])
        packets,drops=struct.unpack('II',s.getsockopt(263,6,8))
    save(Path(output),dict(outer_datagrams=total,directions=dict(counts),size_histogram=dict(sizes),types=dict(types),
        transport_prefix_unique=len(prefixes),capture_packets=packets,capture_drops=drops,
        note='Length/type metadata only. No payloads stored; no timing/camouflage equivalence claim.'))

def make_plan(args):
    if args.suite=='smoke':return [dict(case='smoke',held=8,flows=1,direction='up',rtt=70,loss=0,rate_per_flow=0,bytes_per_flow=2**20,settle_seconds=0,timeout=90)]
    cases=[]
    for held in [0,8]:
        for flows in [1,4]:
            for direction in ['up','down']:
                cases.append(dict(case=f'held{held}-flows{flows}-{direction}',held=held,flows=flows,direction=direction,rtt=70,loss=0,rate_per_flow=0,bytes_per_flow=16*2**20//flows,settle_seconds=0,timeout=120))
    for direction in ['up','down']:
        cases.append(dict(case=f'fixed{args.fixed_rate_mbps:g}-{direction}',held=8,flows=1,direction=direction,rtt=70,loss=0,rate_per_flow=int(args.fixed_rate_mbps*1_000_000),bytes_per_flow=args.fixed_bytes_mib*2**20,settle_seconds=0,timeout=150))
    if args.suite=='full':
        for direction in ['up','down']:
            cases.append(dict(case=f'loss005-{direction}',held=8,flows=1,direction=direction,rtt=70,loss=.05,rate_per_flow=0,bytes_per_flow=16*2**20,settle_seconds=0,timeout=180))
        cases.append(dict(case='idle15-regrowth',held=8,flows=1,direction='up',rtt=70,loss=0,rate_per_flow=0,bytes_per_flow=16*2**20,prime_held_bytes=128*1024,settle_seconds=15,timeout=180))
    return cases

async def main(args):
    assert os.geteuid()==0,'root required for owned network namespace'
    os.sched_setaffinity(0,{6})
    assert len(os.sched_getaffinity(0))==1
    baseline=Path(args.baseline).resolve();candidate=Path(args.candidate).resolve();assert baseline.is_file() and candidate.is_file()
    args.output.mkdir(parents=True,exist_ok=False);out=args.output.resolve()
    assert not Path('/var/run/netns/'+NS).exists(),'owned namespace name already in use'
    assert not Path('/sys/class/net/'+VETH).exists(),'owned veth name already in use'
    assert not Path('/var/run/amneziawg/'+AWG+'.sock').exists(),'owned AWG name in use'
    awgtool=Path(args.awg_tool).resolve();awggo=Path(args.awg_go).resolve();assert awgtool.is_file() and awggo.is_file()
    original_mode=network_mode();containers=command(['docker','ps','-q'],text=True).split() if args.check_containers else None
    procs=[];rows=[];created_ns=False;created_veth=False;cap=None
    before_links=command(['ip','-j','link'],text=True);runtime=None
    save(out/'manifest.json',dict(binaries={n:dict(path=str(p),sha256=sha(p),bytes=p.stat().st_size) for n,p in [('baseline',baseline),('candidate',candidate),('official_awg',awggo)]},
      kernel=command(['uname','-a'],text=True).strip(),workers=args.workers,client_cpu=0,peer_cpus=[2,3,4,5],generator_cpu=6,sink_cpu=7,
      profile=PROFILE,mtu=1380,original_wsl_mode=original_mode,containers=containers,suite=args.suite,repeats=args.repeats,
      capture_enabled=not args.no_capture,fixed_rate_mbps=args.fixed_rate_mbps,fixed_bytes_mib=args.fixed_bytes_mib,
      notes=['Local x86 functional/performance fixture, not ARM/router or general WAN evidence.','Netem on only owned outer veth halves gives requested approximate RTT.','Process RSS excludes kernel queues. Short echo samples do not establish p99.','Fixed-rate controls must be compared at equal actually delivered rates; fallback can fail to reach requested rate.','When enabled, outer metadata capture adds local overhead and is not a timing equivalence test. No outer-capture evidence is claimed by no-capture runs.']))
    try:
        runtime=Path(tempfile.mkdtemp(prefix='awg-adaptive14-',dir='/tmp'));runtime.chmod(0o700)
        for source,name in [(awgtool,'awg'),(awggo,'amneziawg-go')]:
            import shutil
            shutil.copyfile(source,runtime/name);(runtime/name).chmod(0o700)
        def key():
            sk=command([str(runtime/'awg'),'genkey'],text=True).strip();pk=command([str(runtime/'awg'),'pubkey'],input=sk+'\n',text=True).strip();return sk,pk
        sk,sp=key();ck,cp=key()
        command(['ip','netns','add',NS]);created_ns=True
        command(['ip','link','add',VETH,'type','veth','peer','name',PEER]);created_veth=True
        command(['ip','link','set',PEER,'netns',NS]);command(['ip','addr','add',OUTER_LOCAL+'/30','dev',VETH]);command(['ip','link','set',VETH,'up'])
        ns('ip','link','set','lo','up');ns('ip','addr','add',OUTER_PEER+'/30','dev',PEER);ns('ip','link','set',PEER,'up')
        # Segment before netem so loss/delay and AF_PACKET length metadata refer
        # to ordinary UDP packets rather than veth GSO superpackets. The client
        # retains its production UDP_SEGMENT implementation; the kernel performs
        # its ordinary software fallback on these owned interfaces only.
        command(['ethtool','-K',VETH,'gro','off','gso','off','tso','off','tx-udp-segmentation','off'])
        ns('ethtool','-K',PEER,'gro','off','gso','off','tso','off','tx-udp-segmentation','off')
        (out/'veth-client-features.txt').write_text(command(['ethtool','-k',VETH],text=True))
        (out/'veth-peer-features.txt').write_text(ns('ethtool','-k',PEER,text=True))
        peerlog=(out/'official-peer.log').open('wb');peer=spawn(['ip','netns','exec',NS,str(runtime/'amneziawg-go'),'-f',AWG],peerlog,[2,3,4,5],dict(os.environ,GOMAXPROCS='4',LOG_LEVEL='error'));procs.append(peer)
        deadline=time.monotonic()+8
        while not Path('/var/run/amneziawg/'+AWG+'.sock').exists():
            assert peer.poll() is None,'official AWG exited'
            if time.monotonic()>deadline:raise TimeoutError('official AWG UAPI')
            await asyncio.sleep(.1)
        cfg=runtime/'peer.conf';cfg.write_text('[Interface]\nPrivateKey='+sk+'\nListenPort='+str(PORT)+'\n'+''.join(f'{k.upper()}={v}\n' for k,v in PROFILE.items())+'[Peer]\nPublicKey='+cp+'\nAllowedIPs='+CLIENT+'/32\n');cfg.chmod(0o600)
        ns(str(runtime/'awg'),'setconf',AWG,str(cfg));cfg.unlink()
        ns('ip','addr','add',INNER+'/30','dev',AWG);ns('ip','link','set',AWG,'mtu','1380','up')
        ready=runtime/'sink.ready';sinklog=(out/'sink.log').open('wb');sink=spawn(['ip','netns','exec',NS,sys.executable,str(Path(__file__).resolve()),'serve','--ready',str(ready)],sinklog,[7]);procs.append(sink)
        deadline=time.monotonic()+8
        while not ready.exists():
            if time.monotonic()>deadline:raise TimeoutError('sink ready')
            await asyncio.sleep(.1)
        config=runtime/'client.json';config.write_text(json.dumps(dict(log=dict(level='error'),inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=SOCKS)],endpoints=[dict(type='wireguard',tag='awg',system=False,mtu=1380,address=[CLIENT+'/32'],private_key=ck,peers=[dict(address=OUTER_PEER,port=PORT,public_key=sp,allowed_ips=[INNER+'/32'])],**PROFILE)],route=dict(final='awg'))));config.chmod(0o600)
        plan=make_plan(args)
        if args.cases:
            wanted=set(args.cases.split(','));plan=[c for c in plan if c['case'] in wanted]
            assert plan and wanted=={c['case'] for c in plan},'unknown --cases selection'
        for repeat in range(args.repeats):
            for case in plan:
                for label,binary in ([('baseline',baseline),('candidate',candidate)] if repeat%2==0 else [('candidate',candidate),('baseline',baseline)]):
                    delay=case['rtt']/2
                    q=['netem','delay',str(delay)+'ms','limit','10000']
                    if case['loss']:q+=['loss','random',str(case['loss'])+'%']
                    command(['tc','qdisc','replace','dev',VETH,'root',*q]);ns('tc','qdisc','replace','dev',PEER,'root',*q)
                    stem=f'{repeat}-{case["case"]}-{label}';log=(out/(stem+'.log')).open('wb')
                    proc=spawn([str(binary),'run','-c',str(config)],log,[0],dict(os.environ,XRUST_WORKERS=str(args.workers),TACHYON_WORKERS=str(args.workers)));procs.append(proc)
                    stopfile=runtime/'capture.stop';stopfile.unlink(missing_ok=True)
                    metadata=out/(stem+'.outer.json')
                    if not args.no_capture:
                        caplog=(out/(stem+'.capture.log')).open('wb')
                        cap=spawn([sys.executable,str(Path(__file__).resolve()),'capture','--output',str(metadata),'--stopfile',str(stopfile)],caplog,[7]);procs.append(cap)
                    try:
                        for _ in range(100):
                            try:r,w=await socks();w.close();await w.wait_closed();break
                            except (ConnectionError,AssertionError,asyncio.IncompleteReadError):
                                assert proc.poll() is None,'client exited';await asyncio.sleep(.05)
                        else:raise TimeoutError('client ready')
                        await asyncio.wait_for(asyncio.sleep(.15),3)
                        ps=proc_stats(peer.pid);gen=time.process_time()
                        encrypted_before=list(map(int,ns(str(runtime/'awg'),'show',AWG,'transfer',text=True).split()[1:]))
                        row=await batch(case,proc.pid)
                        pa=proc_stats(peer.pid)
                        row.update(case=case,variant=label,repeat=repeat,generator_cpu_s=time.process_time()-gen,
                                   peer_cpu_s=pa['cpu_s']-ps['cpu_s'],peer_cpu_pct=100*(pa['cpu_s']-ps['cpu_s'])/(pa['t']-ps['t']))
                        row['qdisc_client']=command(['tc','-s','qdisc','show','dev',VETH],text=True)
                        row['qdisc_peer']=ns('tc','-s','qdisc','show','dev',PEER,text=True)
                        encrypted_after=list(map(int,ns(str(runtime/'awg'),'show',AWG,'transfer',text=True).split()[1:]))
                        row['tunnel_delta']=dict(rx=encrypted_after[0]-encrypted_before[0],tx=encrypted_after[1]-encrypted_before[1])
                        row['latest_handshake']=int(ns(str(runtime/'awg'),'show',AWG,'latest-handshakes',text=True).split()[1])
                        assert row['latest_handshake']>=time.time()-180,'no fresh AWG handshake'
                        assert row['tunnel_delta']['rx' if case['direction']=='up' else 'tx']>=row['payload'],'payload bypassed tunnel'
                        row['peer_socket_drop_delta']=pa['drops']-ps['drops']
                        rows.append(row);save(out/'measurements.json',rows)
                        print(repeat,case['case'],label,round(row['mbit_s'],2),'CPU/GiB',round(row['cpu_s_gib'],2),'RSS',row['rss_peak_kib'],'drops',row['drops'],flush=True)
                    finally:
                        stopfile.touch();terminate(cap);cap=None;terminate(proc)
                        for p in [metadata.with_suffix(metadata.suffix+'.ready')]:p.unlink(missing_ok=True)
        return out
    finally:
        for p in reversed(procs):terminate(p)
        if created_veth:subprocess.run(['ip','link','del',VETH],capture_output=True)
        if created_ns:subprocess.run(['ip','netns','del',NS],capture_output=True)
        if runtime:
            import shutil
            shutil.rmtree(runtime)
        checks=dict(namespace_removed=not Path('/var/run/netns/'+NS).exists(),veth_removed=not Path('/sys/class/net/'+VETH).exists(),
          runtime_removed=not runtime or not runtime.exists(),wsl_mode_unchanged=network_mode()==original_mode,
          same_containers=containers is None or sorted(command(['docker','ps','-q'],text=True).split())==sorted(containers))
        save(out/'cleanup.json',checks);assert all(checks.values()),checks

def parse():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='action',required=True)
    s=sub.add_parser('serve');s.add_argument('--ready',required=True)
    c=sub.add_parser('capture');c.add_argument('--output',required=True);c.add_argument('--stopfile',required=True)
    r=sub.add_parser('run');r.add_argument('--baseline',required=True);r.add_argument('--candidate',required=True)
    r.add_argument('--output',type=Path,required=True);r.add_argument('--suite',choices=['smoke','main','full'],default='main');r.add_argument('--repeats',type=int,default=3);r.add_argument('--workers',type=int,default=1)
    r.add_argument('--awg-go',required=True,help='official independent amneziawg-go Linux executable')
    r.add_argument('--awg-tool',required=True,help='matching official awg configuration tool')
    r.add_argument('--check-containers',action='store_true');r.add_argument('--cases',default='',help='comma-separated exact case names; narrows suite')
    r.add_argument('--no-capture',action='store_true',help='disable AF_PACKET process for lower-overhead performance confirmation')
    r.add_argument('--fixed-rate-mbps',type=float,default=10.0);r.add_argument('--fixed-bytes-mib',type=int,default=16)
    return p.parse_args()
if __name__=='__main__':
    a=parse()
    if a.action=='serve':asyncio.run(serve(a.ready))
    elif a.action=='capture':capture(a.output,a.stopfile)
    else:
        def stop(*_):raise RuntimeError('bounded fixture interrupted')
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop);signal.signal(signal.SIGALRM,stop);signal.alarm(3000)
        asyncio.run(main(a))
