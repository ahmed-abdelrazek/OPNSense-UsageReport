#!/usr/local/bin/python3
"""
    Copyright (c) 2026 Ahmed Abdelrazek
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    --------------------------------------------------------------------------------------
    Per-device internet usage report (Insight NetFlow + Kea/Hostwatch device mapping).

      usage-report.py --from 2026-09-01 --to 2026-09-22      per device totals (inclusive dates)
      usage-report.py --from ... --to ... --by-day            per device per day
      usage-report.py --from ... --to ... --csv | --json      machine readable output
      usage-report.py --last 7                                last N days incl. today
      usage-report.py --snapshot                              record today's IP->device mapping (cron)
      usage-report.py --lan opt1 --wan wan ...                override interfaces (config names)

    Directions (Insight semantics): a flow leaving the firewall towards a client is recorded on the
    LAN interface as direction "out" (download); a client packet entering the firewall is recorded on
    the interface it arrived on as direction "in" (upload). On a bridged LAN uploads arrive on the
    member ports, so those are included when they are part of the NetFlow capture.
"""
import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET

NETFLOW_DIR = '/var/netflow'
NETFLOW_DB = os.path.join(NETFLOW_DIR, 'src_addr_086400.sqlite')
DETAILS_DB = os.path.join(NETFLOW_DIR, 'src_addr_details_086400.sqlite')
HOSTWATCH_DB = '/var/db/hostwatch/hosts.db'
KEA_LEASES = '/var/db/kea/kea-leases4.csv'
CONFIG_XML = '/conf/config.xml'
SNAP_DIR = '/var/db/usagereport'
SNAP_DB = os.path.join(SNAP_DIR, 'ipmap.sqlite')


class Net:
    """interfaces and LAN network derived from config.xml"""

    def __init__(self, lan='lan', wan='wan'):
        root = ET.parse(CONFIG_XML).getroot()
        ifs = root.find('interfaces')
        lan_node = ifs.find(lan) if ifs is not None else None
        wan_node = ifs.find(wan) if ifs is not None else None
        if lan_node is None or not (lan_node.findtext('if') or '').strip():
            raise SystemExit("interface '%s' not found in config" % lan)
        self.lan_if = lan_node.findtext('if').strip()
        self.wan_if = (wan_node.findtext('if') or '').strip() if wan_node is not None else ''
        ipaddr = (lan_node.findtext('ipaddr') or '').strip()
        subnet = (lan_node.findtext('subnet') or '24').strip()
        try:
            self.network = ipaddress.ip_network('%s/%s' % (ipaddr, subnet), strict=False)
        except ValueError:
            raise SystemExit("interface '%s' has no static IPv4 address" % lan)
        self.gateway = ipaddr
        # upload enters on bridge members when the LAN is a bridge
        self.in_ifs = [self.lan_if]
        if self.lan_if.startswith('bridge'):
            try:
                out = subprocess.run(['ifconfig', self.lan_if], capture_output=True, text=True).stdout
                self.in_ifs += re.findall(r'^\s*member:\s+(\S+)', out, re.M)
            except Exception:
                pass
        # SQL LIKE prefix for cheap pre-filtering (exact membership is checked in python)
        octets = str(self.network.network_address).split('.')
        n = self.network.prefixlen
        self.like_prefix = '.'.join(octets[:3]) + '.' if n >= 24 else \
            '.'.join(octets[:2]) + '.' if n >= 16 else octets[0] + '.' if n >= 8 else ''

    def is_lan(self, ip):
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False


def norm_mac(m):
    return m.lower().strip() if m else ''


def reservations():
    """ip -> (mac, name) from Kea DHCPv4 reservations in config.xml"""
    out = {}
    try:
        root = ET.parse(CONFIG_XML).getroot()
        for r in root.findall('./OPNsense/Kea/dhcp4/reservations/reservation'):
            ip = (r.findtext('ip_address') or '').strip()
            mac = norm_mac(r.findtext('hw_address'))
            name = (r.findtext('hostname') or '').strip() or (r.findtext('description') or '').strip()
            if ip:
                out[ip] = (mac, name)
    except Exception as e:
        print("warn: reservations unreadable: %s" % e, file=sys.stderr)
    return out


def kea_leases():
    """ip -> (mac, hostname) from active Kea leases"""
    out = {}
    if not os.path.exists(KEA_LEASES):
        return out
    try:
        with open(KEA_LEASES) as f:
            for row in csv.DictReader(f):
                if row.get('state', '0') != '0':
                    continue
                out[row['address']] = (norm_mac(row['hwaddr']), (row.get('hostname') or '').rstrip('.'))
    except Exception as e:
        print("warn: kea leases unreadable: %s" % e, file=sys.stderr)
    return out


def arp_table():
    out = {}
    try:
        txt = subprocess.run(['arp', '-an'], capture_output=True, text=True).stdout
        for m in re.finditer(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{17})', txt):
            out[m.group(1)] = norm_mac(m.group(2))
    except Exception:
        pass
    return out


def hostwatch(lan_if):
    """ip -> dict(mac, prev_mac, prev_last_seen, vendor) from Hostwatch (LAN rows preferred)"""
    out = {}
    if not os.path.exists(HOSTWATCH_DB):
        return out
    try:
        con = sqlite3.connect('file:%s?mode=ro' % HOSTWATCH_DB, uri=True)
        rows = con.execute("""select ip_address, ether_address, prev_ether_address, prev_last_seen, organization_name
                              from v_hosts where protocol='inet'
                              order by case when interface_name=? then 0 else 1 end, last_seen desc""",
                           (lan_if,)).fetchall()
        for ip, mac, pmac, pls, org in rows:
            if ip not in out:
                out[ip] = dict(mac=norm_mac(mac), prev_mac=norm_mac(pmac), prev_last_seen=pls, vendor=org or '')
        con.close()
    except Exception as e:
        print("warn: hostwatch unreadable: %s" % e, file=sys.stderr)
    return out


def vendors():
    v = {}
    if not os.path.exists(HOSTWATCH_DB):
        return v
    try:
        con = sqlite3.connect('file:%s?mode=ro' % HOSTWATCH_DB, uri=True)
        for a, n in con.execute("select assignment, organization_name from oui"):
            v[a.upper()] = n
        con.close()
    except Exception:
        pass
    return v


def snap_conn():
    os.makedirs(SNAP_DIR, exist_ok=True)
    con = sqlite3.connect(SNAP_DB)
    con.execute("""create table if not exists ipmap (day text, ip text, mac text, hostname text, source text,
                   primary key (day, ip))""")
    return con


def do_snapshot(net):
    today = dt.date.today().isoformat()
    res, leases, arp = reservations(), kea_leases(), arp_table()
    rows = {}
    for ip, (mac, name) in res.items():
        rows[ip] = (mac, name, 'reservation')
    for ip, (mac, name) in leases.items():
        rows[ip] = (mac, name or rows.get(ip, ('', '', ''))[1], 'kea-lease')
    for ip, mac in arp.items():
        if net.is_lan(ip) and ip not in rows:
            rows[ip] = (mac, '', 'arp')
    con = snap_conn()
    with con:
        for ip, (mac, name, src) in rows.items():
            con.execute("insert or replace into ipmap(day, ip, mac, hostname, source) values (?,?,?,?,?)",
                        (today, ip, mac, name, src))
    con.close()
    print("snapshot %s: %d addresses recorded" % (today, len(rows)))


def snapshots():
    out = {}
    if not os.path.exists(SNAP_DB):
        return out
    con = sqlite3.connect('file:%s?mode=ro' % SNAP_DB, uri=True)
    for day, ip, mac, host in con.execute("select day, ip, mac, hostname from ipmap"):
        out[(day, ip)] = (mac, host)
    con.close()
    return out


def mac_for(day, ip, snaps, hw, res, leases, arp):
    """best-effort MAC for ip on a given day, and how it was determined"""
    if (day, ip) in snaps and snaps[(day, ip)][0]:
        return snaps[(day, ip)][0], 'snapshot'
    if ip in res:
        return res[ip][0], 'reservation'
    h = hw.get(ip)
    if h:
        pls = (h['prev_last_seen'] or '')[:10]
        if h['prev_mac'] and pls and day <= pls:
            return h['prev_mac'], 'hostwatch-prev'
        return h['mac'], 'hostwatch'
    if ip in leases:
        return leases[ip][0], 'kea-lease'
    if ip in arp:
        return arp[ip], 'arp'
    return '', 'unknown'


def name_for(mac, ips, res, leases, snaps, hw, vend):
    for ip in ips:
        if ip in res and res[ip][0] == mac and res[ip][1]:
            return res[ip][1]
    for ip in ips:
        if ip in leases and leases[ip][0] == mac and leases[ip][1]:
            return leases[ip][1]
    for (d, ip), (m, h) in sorted(snaps.items(), reverse=True):
        if m == mac and h:
            return h
    for ip in ips:
        h = hw.get(ip)
        if h and h['mac'] == mac and h['vendor']:
            return h['vendor']
    v = vend.get(mac.replace(':', '')[:6].upper()) if mac else None
    return v or ''


def query_usage(net, date_from, date_to):
    """returns rows (day, ip, down_bytes, up_bytes) for LAN clients and WAN totals.

    Internet-only accounting comes from the details table (has dst_addr, ~62 days retention):
      download: if=LAN, direction=out, src=client, dst not LAN/multicast/broadcast
      upload:   if in LAN+members, direction=in, src=client, dst not LAN/multicast/broadcast
    Days older than the details retention fall back to the per-address totals table (no dst filter).
    """
    not_local = """dst_addr not like ? and dst_addr not like '255.%' and dst_addr not like '0.%'
                   and not (cast(substr(dst_addr, 1, instr(dst_addr, '.') - 1) as integer) between 224 and 239)"""
    like = net.like_prefix + '%'
    rows = {}
    det_min = None
    q_in = ','.join('?' * len(net.in_ifs))
    if os.path.exists(DETAILS_DB):
        con = sqlite3.connect('file:%s?mode=ro' % DETAILS_DB, uri=True)
        det_min = con.execute("select min(date(mtime)) from timeserie").fetchone()[0]
        sql = """
            select day, ip, sum(down), sum(up) from (
              select date(mtime) as day, src_addr as ip, octets as down, 0 as up from timeserie
               where "if"=? and direction='out' and src_addr like ? and date(mtime) between ? and ? and %s
              union all
              select date(mtime) as day, src_addr as ip, 0 as down, octets as up from timeserie
               where "if" in (%s) and direction='in' and src_addr like ? and date(mtime) between ? and ? and %s
            ) group by day, ip""" % (not_local, q_in, not_local)
        params = [net.lan_if, like, date_from, date_to, like] + net.in_ifs + [like, date_from, date_to, like]
        for day, ip, down, up in con.execute(sql, params):
            if net.is_lan(ip):
                rows[(day, ip)] = [down or 0, up or 0]
        con.close()

    con = sqlite3.connect('file:%s?mode=ro' % NETFLOW_DB, uri=True)
    if det_min is None or det_min > date_from:
        if det_min:
            fb_to = min(date_to, (dt.date.fromisoformat(det_min) - dt.timedelta(days=1)).isoformat())
        else:
            fb_to = date_to
        sql = """
            select date(mtime), src_addr,
                   sum(case when "if"=? and direction='out' then octets else 0 end),
                   sum(case when "if" in (%s) and direction='in' then octets else 0 end)
              from timeserie where src_addr like ? and date(mtime) between ? and ?
             group by 1, 2""" % q_in
        for day, ip, down, up in con.execute(sql, [net.lan_if] + net.in_ifs + [like, date_from, fb_to]):
            if (day, ip) not in rows and net.is_lan(ip):
                rows[(day, ip)] = [down or 0, up or 0]
    wan = None
    if net.wan_if:
        wan = con.execute("""select sum(case when direction='in' then octets else 0 end),
                                    sum(case when direction='out' then octets else 0 end)
                             from timeserie where "if"=? and date(mtime) between ? and ?""",
                          (net.wan_if, date_from, date_to)).fetchone()
    con.close()
    return [(d, ip, v[0], v[1]) for (d, ip), v in rows.items()], wan


def gb(b):
    return (b or 0) / 1e9


NOTES = [
    'Download = internet to device, Upload = device to internet, Total = both. LAN-to-LAN traffic is excluded.',
    'Days are UTC days as stored by Insight. Upload requires the LAN (and bridge member) interfaces in the NetFlow capture.',
    'Devices marked approx. were identified from Hostwatch/ARP history; exact per-day mapping comes from the daily snapshot.',
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--from', dest='date_from')
    ap.add_argument('--to', dest='date_to')
    ap.add_argument('--last', type=int, help='last N days including today')
    ap.add_argument('--by-day', action='store_true')
    ap.add_argument('--csv', action='store_true')
    ap.add_argument('--json', action='store_true', help='machine readable output (used by the web UI)')
    ap.add_argument('--snapshot', action='store_true')
    ap.add_argument('--lan', default='lan', help='LAN interface (config name, default lan)')
    ap.add_argument('--wan', default='wan', help='WAN interface (config name, default wan)')
    a = ap.parse_args()

    net = Net(a.lan, a.wan)
    if a.snapshot:
        do_snapshot(net)
        return
    today = dt.date.today()
    if a.last:
        a.date_to = today.isoformat()
        a.date_from = (today - dt.timedelta(days=a.last - 1)).isoformat()
    if not (a.date_from and a.date_to):
        ap.error('give --from/--to or --last N (or --snapshot)')
    for d in (a.date_from, a.date_to):
        dt.date.fromisoformat(d)
    if a.date_from > a.date_to:
        a.date_from, a.date_to = a.date_to, a.date_from

    rows, wan = query_usage(net, a.date_from, a.date_to)
    res, leases, arp = reservations(), kea_leases(), arp_table()
    hw, snaps, vend = hostwatch(net.lan_if), snapshots(), vendors()

    dev = {}
    for day, ip, down, up in rows:
        if ip == net.gateway or ip == str(net.network.broadcast_address):
            continue
        mac, how = mac_for(day, ip, snaps, hw, res, leases, arp)
        key = mac or ('ip:' + ip)
        d = dev.setdefault(key, dict(mac=mac, ips=set(), down=0, up=0, days={}, how=set()))
        d['ips'].add(ip)
        d['down'] += down or 0
        d['up'] += up or 0
        d['how'].add(how)
        dd = d['days'].setdefault(day, [0, 0])
        dd[0] += down or 0
        dd[1] += up or 0
    for d in dev.values():
        d['name'] = name_for(d['mac'], sorted(d['ips']), res, leases, snaps, hw, vend) or \
            ('unknown device' if d['mac'] else 'unknown (no MAC)')

    order = sorted(dev.values(), key=lambda d: d['down'] + d['up'], reverse=True)
    tdn = sum(d['down'] for d in order)
    tup = sum(d['up'] for d in order)

    if a.json:
        out = dict(date_from=a.date_from, date_to=a.date_to, lan_if=net.lan_if, in_ifs=net.in_ifs,
                   devices=[], totals={}, wan={}, notes=NOTES)
        for d in order:
            out['devices'].append(dict(
                name=d['name'], mac=d['mac'], ips=sorted(d['ips']),
                download_gb=round(gb(d['down']), 3), upload_gb=round(gb(d['up']), 3),
                total_gb=round(gb(d['down'] + d['up']), 3),
                exact=bool(d['how'] <= {'snapshot', 'reservation'}),
                mapping=sorted(d['how']),
                days={day: dict(download_gb=round(gb(v[0]), 3), upload_gb=round(gb(v[1]), 3),
                                total_gb=round(gb(v[0] + v[1]), 3)) for day, v in sorted(d['days'].items())}))
        out['totals'] = dict(download_gb=round(gb(tdn), 3), upload_gb=round(gb(tup), 3), total_gb=round(gb(tdn + tup), 3))
        if wan:
            out['wan'] = dict(download_gb=round(gb(wan[0]), 3), upload_gb=round(gb(wan[1]), 3),
                              total_gb=round(gb((wan[0] or 0) + (wan[1] or 0)), 3))
        print(json.dumps(out))
        return

    if a.csv:
        w = csv.writer(sys.stdout)
        if a.by_day:
            w.writerow(['day', 'device', 'mac', 'ips', 'download_gb', 'upload_gb', 'total_gb'])
            for d in order:
                for day in sorted(d['days']):
                    dn, up = d['days'][day]
                    w.writerow([day, d['name'], d['mac'], ' '.join(sorted(d['ips'])),
                                '%.3f' % gb(dn), '%.3f' % gb(up), '%.3f' % gb(dn + up)])
        else:
            w.writerow(['device', 'mac', 'ips', 'download_gb', 'upload_gb', 'total_gb', 'mapping'])
            for d in order:
                w.writerow([d['name'], d['mac'], ' '.join(sorted(d['ips'])), '%.3f' % gb(d['down']),
                            '%.3f' % gb(d['up']), '%.3f' % gb(d['down'] + d['up']), '+'.join(sorted(d['how']))])
        return

    print("Internet usage per device, %s to %s (inclusive), LAN=%s upload-in=%s\n" %
          (a.date_from, a.date_to, net.lan_if, ','.join(net.in_ifs)))
    print("%-28s %-18s %12s %10s %10s  %s" % ('Device', 'MAC', 'Download GB', 'Upload GB', 'Total GB', 'IPs'))
    print('-' * 100)
    for d in order:
        flag = '' if d['how'] <= {'snapshot', 'reservation'} else ' *'
        print("%-28s %-18s %12.2f %10.2f %10.2f  %s" % ((d['name'][:26] + flag), d['mac'] or '-', gb(d['down']),
                                                      gb(d['up']), gb(d['down'] + d['up']), ' '.join(sorted(d['ips']))))
        if a.by_day:
            for day in sorted(d['days']):
                dn, up = d['days'][day]
                print("    %-24s %-18s %12.2f %10.2f %10.2f" % (day, '', gb(dn), gb(up), gb(dn + up)))
    print('-' * 100)
    print("%-28s %-18s %12.2f %10.2f %10.2f" % ('All devices', '', gb(tdn), gb(tup), gb(tdn + tup)))
    if wan:
        print("%-28s %-18s %12.2f %10.2f %10.2f" % ('WAN (%s) cross-check' % net.wan_if, '', gb(wan[0]), gb(wan[1]),
                                                   gb((wan[0] or 0) + (wan[1] or 0))))
    print()
    for n in NOTES:
        print(n)


if __name__ == '__main__':
    main()
