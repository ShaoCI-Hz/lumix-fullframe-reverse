import os
import re
import sys
import traceback

DIR = os.path.join(os.environ['TEMP'], 'pansite2')

# 鏈鸿韩鏈哄瀷(鎺掗櫎闀滃ご:浠?s_r/s_e/s_s/s_x 寮€澶?
BODIES = {
    's1': 'DC-S1', 's1r': 'DC-S1R', 's1h': 'DC-S1H', 's5': 'DC-S5',
    'bs1h': 'DC-BS1H', 's5m2': 'DC-S5M2', 's5m2x': 'DC-S5M2X',
    's9': 'DC-S9', 's1rm2': 'DC-S1RM2', 's1m2': 'DC-S1M2', 's1m2es': 'DC-S1M2ES',
}

try:
    print('=== 鍚勬満鍨嬪浐浠舵竻鍗?===')
    print(f'{"鏈哄瀷":12} {"鐗堟湰":8} {"鍥轰欢鏂囦欢":22} {"瑙ｅ帇鍚?:22} {"澶у皬":>14} {"鏇存柊鏃?:>12}')
    results = {}
    for code, model in BODIES.items():
        p = os.path.join(DIR, f'dl_{code}.html')
        if not os.path.exists(p):
            print(f'{model:12} (椤甸潰缂哄け)')
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
        sizes = list(dict.fromkeys(re.findall(r'([\d,]{4,})\s*銉愩偆銉?, txt)))
        dates = list(dict.fromkeys(re.findall(r'(20\d\d)骞碶s*(\d+)鏈圽s*(\d+)鏃?, txt)))
        d = ''
        if dates:
            y, mo, dd = dates[0]
            d = f'{y}-{mo.zfill(2)}-{dd.zfill(2)}'
        results[model] = dict(code=code, ver=vers[0] if vers else '?',
                              zips=zips, bins=bins,
                              size=sizes[0] if sizes else '?', date=d)
        print(f'{model:12} {results[model]["ver"]:8} {str(zips[:1]):22} {str(bins[:1]):22} {str(sizes[:1]):>14} {d:>12}')

    print()
    print('=== 鍙洿鎺ヤ笅杞界殑鍥轰欢鐩撮摼(鎺ㄦ祴)===')
    for model, r in results.items():
        if r['zips']:
            print(f'  {model:12} https://panasonic.jp/support/share2/eww/com/dsc/ff/zip/{r["zips"][0]}')

    # 棰濆:妫€鏌ラ〉闈腑鏄惁鏈夊巻鍙茬増鏈摼鎺?    print()
    print('=== 鍘嗗彶鐗堟湰绾跨储(椤甸潰涓殑涓嬭浇纭椤甸摼鎺?===')
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
