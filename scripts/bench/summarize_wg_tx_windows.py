#!/usr/bin/env python3
"""Summarize paired local evidence without dropping slow samples."""
import argparse,collections,json,statistics
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('output',type=Path);args=p.parse_args();R=args.output
rows=json.loads((R/'measurements.json').read_text());groups=collections.defaultdict(list);metadata=[]
capture_enabled=json.loads((R/'manifest.json').read_text()).get('capture_enabled',True)
for x in rows:
    groups[x['case']['case'],x['variant']].append(x)
    if capture_enabled:
        path=R/f"{x['repeat']}-{x['case']['case']}-{x['variant']}.outer.json"
        d=json.loads(path.read_text());metadata.append(dict(case=x['case']['case'],variant=x['variant'],repeat=x['repeat'],**d))
        assert d['outer_datagrams']>0,'no outer test traffic captured'
        assert any(k.endswith(':h4') and v>0 for k,v in d['types'].items()),'custom H4 transport header absent'
        assert d['transport_prefix_unique']>1,'random transport prefix not observed'
summary=[]
for (case,v),g in sorted(groups.items()):
    vals=[x['mbit_s'] for x in g]
    y=dict(case=case,variant=v,n=len(g),mbit_s_median=statistics.median(vals),mbit_s_range=[min(vals),max(vals)],
           cpu_s_gib_median=statistics.median(x['cpu_s_gib'] for x in g),rss_peak_kib_median=statistics.median(x['rss_peak_kib'] for x in g),
           echo_median_ms=statistics.median(x['echo_median_ms'] for x in g),client_socket_drops=sum(x['drops'] for x in g),
           peer_socket_drops=sum(x['peer_socket_drop_delta'] for x in g),capture_enabled=capture_enabled,
           capture_drops=sum(d['capture_drops'] for d in metadata if d['case']==case and d['variant']==v) if capture_enabled else None)
    summary.append(y);print(case,v,'speed',round(y['mbit_s_median'],2),[round(a,2) for a in y['mbit_s_range']],
        'CPU/GiB',round(y['cpu_s_gib_median'],2),'RSS',y['rss_peak_kib_median'],'echo',round(y['echo_median_ms'],2),'drops',y['client_socket_drops'])
pairs=[]
for case in sorted({x['case']['case'] for x in rows}):
    for repeat in sorted({x['repeat'] for x in rows}):
        pair={x['variant']:x for x in rows if x['case']['case']==case and x['repeat']==repeat}
        if set(pair)=={'baseline','candidate'}:
            b=pair['baseline'];c=pair['candidate'];pairs.append(dict(case=case,repeat=repeat,baseline=b['mbit_s'],candidate=c['mbit_s'],ratio=c['mbit_s']/b['mbit_s']))
(R/'summary.json').write_text(json.dumps(summary,indent=2));(R/'paired.json').write_text(json.dumps(pairs,indent=2));(R/'outer-summary.json').write_text(json.dumps(metadata,indent=2))
assert all(json.loads((R/'cleanup.json').read_text()).values())
print('VERIFIED',len(rows),'batches',sum(len(x['transfers']) for x in rows),'bulk transfers;',
      'custom H4 and random-prefix checks pass;' if capture_enabled else 'capture disabled: no outer-shape or camouflage evidence in this series;',
      'owned resources cleaned')
