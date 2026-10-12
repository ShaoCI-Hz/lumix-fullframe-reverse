import re
import ssl
import sys
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

BASE = 'https://av.jpn.support.panasonic.com/support/dsc/download/'


def get(url):
    req = urllib.request.Request(url, headers={
        'User-Agent': UA,
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'ja,en;q=0.8',
    })
    return urllib.request.urlopen(req, timeout=30, context=ctx).read()


def dec(raw):
    for e in ('utf-8', 'shift_jis'):
        try:
            return raw.decode(e)
        except Exception:
            pass
    return raw.decode('utf-8', 'replace')


try:
    # 全画幅机型列表页
    html = dec(get(BASE + 'index4.html'))
    models = []
    # window.open("ff/dl/xxx.html", ...)
    for m in re.finditer(r'window\.open\(\s*["\']ff/dl/(\w+)\.html', html):
        models.append(m.group(1))
    models = list(dict.fromkeys(models))
    print(f'=== 全画幅机型下载页 ({len(models)} 个) ===')
    for m in models:
        print(f'  {m}')

    # 机型名 → 型号
    name_map = {}
    for m in re.finditer(r'<td[^>]*>\s*(DC-[A-Z0-9]+)\s*</td>', html):
        pass
    # 从文本提取 品番
    plain = re.sub(r'<[^>]+>', '\n', html)
    lines = [l.strip() for l in plain.split('\n') if l.strip()]
    dcs = [l for l in lines if re.fullmatch(r'DC-[A-Z0-9]+', l)]
    print(f'\n=== 机型型号 ===')
    for d in dict.fromkeys(dcs):
        print(f'  {d}')

    print()
    print('=== 各机型固件文件名 ===')
    for m in models:
        try:
            page = dec(get(BASE + f'ff/dl/{m}.html'))
            zips = list(dict.fromkeys(re.findall(r'([A-Za-z0-9_\-]+\.zip)', page)))
            size = re.findall(r'([\d,]+)\s*バイト', page)
            ver = re.findall(r'Ver\.(\d+\.\d+)', page)
            bins = list(dict.fromkeys(re.findall(r'([A-Za-z0-9_\-]+\.bin)', page)))
            print(f'  {m:8} ver={ver[:1]} zip={zips} bin={bins} size={size[:1]}')
        except Exception as e:
            print(f'  {m:8} FAIL {str(e)[:50]}')

except Exception:
    import traceback
    traceback.print_exc()
    sys.exit(1)
