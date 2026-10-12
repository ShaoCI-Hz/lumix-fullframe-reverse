import os
import re
import sys
import traceback

DIR = os.path.join(os.environ['TEMP'], 'pansite2')

# 机身机型(排除镜头:以 s_r/s_e/s_s/s_x 开头)
BODIES = {
    's1': 'DC-S1', 's1r': 'DC-S1R', 's1h': 'DC-S1H', 's5': 'DC-S5',
    'bs1h': 'DC-BS1H', 's5m2': 'DC-S5M2', 's5m2x': 'DC-S5M2X',
    's9': 'DC-S9', 's1rm2': 'DC-S1RM2', 's1m2': 'DC-S1M2', 's1m2es': 'DC-S1M2ES',
}

try:
    print('=== 各机型固件清单 ===')
    print(f'{"机型":12} {"版本":8} {"固件文件":22} {"解压后":22} {"大小":>14} {"更新日":>12}')
    results = {}
    for code, model in BODIES.items():
        p = os.path.join(DIR, f'dl_{code}.html')
        if not os.path.exists(p):
            print(f'{model:12} (页面缺失)')
            continue
        raw = open(p, 'rb').read()
        for enc in ('utf-8', 'shift_jis'):
            try:
                txt = raw.decode(enc)
                break
            except Exception:
                pass
        else:
            txt = raw.decode('utf-8', 'replace')

        zips = list(dict.fromkeys(re.findall(r'([A-Za-z0-9_\-]+\.zip)', txt)))
        bins = list(dict.fromkeys(re.findall(r'([A-Za-z0-9_\-]+\.bin)', txt)))
        vers = list(dict.fromkeys(re.findall(r'Ver\.(\d+\.\d+)', txt)))
        sizes = list(dict.fromkeys(re.findall(r'([\d,]{4,})\s*バイト', txt)))
        dates = list(dict.fromkeys(re.findall(r'(20\d\d)年\s*(\d+)月\s*(\d+)日', txt)))
        d = ''
        if dates:
            y, mo, dd = dates[0]
            d = f'{y}-{mo.zfill(2)}-{dd.zfill(2)}'
        results[model] = dict(code=code, ver=vers[0] if vers else '?',
                              zips=zips, bins=bins,
                              size=sizes[0] if sizes else '?', date=d)
        print(f'{model:12} {results[model]["ver"]:8} {str(zips[:1]):22} {str(bins[:1]):22} {str(sizes[:1]):>14} {d:>12}')

    print()
    print('=== 可直接下载的固件直链(推测)===')
    for model, r in results.items():
        if r['zips']:
            print(f'  {model:12} https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/{r["zips"][0]}')

    # 额外:检查页面中是否有历史版本链接
    print()
    print('=== 历史版本线索(页面中的下载确认页链接)===')
    for code in ('s5m2x', 's5m2', 's1h', 's5'):
        p = os.path.join(DIR, f'dl_{code}.html')
        if not os.path.exists(p):
            continue
        txt = open(p, 'rb').read().decode('utf-8', 'replace')
        links = list(dict.fromkeys(re.findall(r'href="([^"]*_dl\.html)"', txt)))
        locs = list(dict.fromkeys(re.findall(r"location\.href='([^']+)'", txt)))
        print(f'  {code}: links={links} loc={locs[:2]}')

except Exception:
    traceback.print_exc()
    sys.exit(1)
