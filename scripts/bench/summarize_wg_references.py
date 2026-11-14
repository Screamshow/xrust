#!/usr/bin/env python3
"""Summarize native/official-Go AWG comparisons and idle memory recovery.

Keeps every repeat and names metrics by their actual accounting scope. Process
memory excludes kernel TCP/UDP queues; the Go variant includes its direct relay.
"""
# SPDX-License-Identifier: GPL-3.0-only
import argparse
import collections
import json
import statistics
from pathlib import Path


def describe(values):
    return dict(median=statistics.median(values),minimum=min(values),maximum=max(values))


def summarize(folder, comparisons):
    rows=json.loads((folder/'measurements.json').read_text())
    completion=json.loads((folder/'completion.json').read_text())
    assert completion['complete'] and completion['expected_rows']==len(rows),'incomplete series'
    cleanup=json.loads((folder/'cleanup.json').read_text())
    assert all(cleanup.values()),cleanup
    manifest=json.loads((folder/'manifest.json').read_text())
    grouped=collections.defaultdict(list)
    for row in rows:
        assert row['status']=='OK' and row['drops']==0 and row['peer_socket_drop_delta']==0
        grouped[row['case']['case'],row['variant']].append(row)
    summary=[]
    for (case,label),items in sorted(grouped.items()):
        value=dict(case=case,variant=label,repeats=len(items),payload_bytes=[r['payload'] for r in items],
                   mbit_s=describe([r['mbit_s'] for r in items]),
                   process_cpu_s_gib=describe([r['cpu_s_gib'] for r in items]),
                   process_cpu_percent_one_cpu=describe([r['cpu_pct'] for r in items]),
                   peer_cpu_percent_one_cpu=describe([r['peer_cpu_pct'] for r in items]),
                   process_peak_rss_kib=describe([r['rss_peak_kib'] for r in items]),
                   echo_median_ms=describe([r['echo_median_ms'] for r in items]),memory_phases={},
                   live_held_connection_phases={},
                   configured_netem_loss_percent=sorted({r['case']['loss'] for r in items}),
                   client_socket_drop_counts=[r['drops'] for r in items],
                   peer_socket_drop_counts=[r['peer_socket_drop_delta'] for r in items],
                   minor_major_page_faults='not collected by this fixture; unavailable')
        if all(r.get('samples') for r in items):
            value['sampled_load_fd_peak']=describe([max(s['fds'] for s in r['samples']) for r in items])
        held_phases=sorted(set.intersection(*(set(k for k,v in r.get('lease_observations',{}).items() if isinstance(v,dict) and 'memory_kib' in v) for r in items)))
        for phase in held_phases:
            snapshots=[r['lease_observations'][phase] for r in items]
            value['live_held_connection_phases'][phase]={key+'_kib':describe([s['memory_kib'][key] for s in snapshots]) for key in ['VmRSS','VmHWM','RssAnon'] if all(key in s['memory_kib'] for s in snapshots)}
            value['live_held_connection_phases'][phase]['fds']=describe([s['fds'] for s in snapshots])
        if held_phases:
            value['same_held_connections_reused']=all(r['lease_observations'].get('same_connections_reused') for r in items)
            value['sampled_rss_peak_including_phase_snapshots_kib']=describe([
                max([r['rss_peak_kib']]+[r['lease_observations'][phase]['memory_kib']['VmRSS'] for phase in held_phases]) for r in items])
        phases=sorted(set.intersection(*(set(r.get('memory_phases',{})) for r in items)))
        for phase in phases:
            snapshots=[r['memory_phases'][phase] for r in items]
            memory={}
            for key in ['VmRSS','VmHWM','RssAnon']:
                values=[s['memory_kib'][key] for s in snapshots if key in s['memory_kib']]
                if values:memory[key+'_kib']=describe(values)
            memory['fds']=describe([s['fds'] for s in snapshots])
            pss=[sum(part['Pss'] for part in s.get('smaps_rollup_kib',{}).values()) for s in snapshots]
            if all(s.get('smaps_rollup_kib') for s in snapshots):memory['Pss_kib']=describe(pss)
            value['memory_phases'][phase]=memory
        recovery=[phase for phase in items[0].get('memory_phases',{}) if phase in phases and phase.startswith('recovery_plus_')]
        if recovery and 'ready' in phases:
            last=recovery[-1]
            value['final_recovery_phase']=last
            value['rss_recovery_minus_ready_kib']=describe([r['memory_phases'][last]['memory_kib']['VmRSS']-r['memory_phases']['ready']['memory_kib']['VmRSS'] for r in items])
            value['rss_peak_minus_recovery_kib']=describe([r['rss_peak_kib']-r['memory_phases'][last]['memory_kib']['VmRSS'] for r in items])
            value['fd_recovery_minus_ready']=describe([r['memory_phases'][last]['fds']-r['memory_phases']['ready']['fds'] for r in items])
        summary.append(value)
        print(case,label,'Mbit/s',round(value['mbit_s']['median'],3),
              'CPU-s/GiB',round(value['process_cpu_s_gib']['median'],3),
              'peak-process-RSS-KiB',value['process_peak_rss_kib']['median'],flush=True)
    pairs=[]
    for specification in comparisons:
        baseline,separator,candidate=specification.partition(':')
        assert separator and baseline and candidate,'--compare BASELINE:CANDIDATE'
        for case in sorted({r['case']['case'] for r in rows}):
            repeats=sorted({r['repeat'] for r in rows if r['case']['case']==case})
            for repeat in repeats:
                pair={r['variant']:r for r in rows if r['case']['case']==case and r['repeat']==repeat}
                if baseline in pair and candidate in pair:
                    old,new=pair[baseline],pair[candidate]
                    assert old['payload']==new['payload'],'unequal payload comparison'
                    pairs.append(dict(case=case,repeat=repeat,baseline=baseline,candidate=candidate,
                      baseline_mbit_s=old['mbit_s'],candidate_mbit_s=new['mbit_s'],rate_ratio=new['mbit_s']/old['mbit_s'],
                      baseline_cpu_s_gib=old['cpu_s_gib'],candidate_cpu_s_gib=new['cpu_s_gib'],
                      baseline_peak_rss_kib=old['rss_peak_kib'],candidate_peak_rss_kib=new['rss_peak_kib']))
    result=dict(summary=summary,paired_repeats=pairs,completion=completion,
      notes=manifest.get('notes',[])+['Recovery intervals are successive, not absolute: +1s then +11s means approximately 12s total.',
        'RSS alone does not prove live allocation or leakage. PSS/RssAnon/FD phase samples supplement it.',
        'VmHWM is historical; summed Go+relay VmHWM is not a simultaneous memory peak.',
        'Page-fault counts are unavailable: the frozen benchmark did not collect minflt/majflt.',
        'For primed-held tests, load sampling starts after priming and idle. Phase snapshots supplement it; they do not establish a continuously observed peak during priming. Bulk CPU/GiB excludes priming/idle/reuse.',
        'Fixed-rate CPU comparisons require equal actually delivered rates; saturated CPU/GiB is a different comparison.'])
    (folder/'reference-summary.json').write_text(json.dumps(result,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder',type=Path)
    parser.add_argument('--compare',action='append',default=[])
    arguments=parser.parse_args()
    summarize(arguments.folder,arguments.compare)
