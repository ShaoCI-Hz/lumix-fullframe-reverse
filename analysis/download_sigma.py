"""
下载 Sigma L 卡口镜头固件(官方直链,免序列号)。

直链模式(已验证 HTTP 200):
    https://www.sigma-global.com/en/support/download/<8字符文件名>.plf

命名规则: <4 字母数字镜头码><4 位版本>
    S02D + 0120  ->  14mm F1.4 DG DN | Art  (A023) v1.2
    A004 + 0140  ->  30mm F1.4 DC DN | Contemporary (C016) v1.4
    S02A + 0130  ->  50mm F2 DG DN | Contemporary (C023) v1.3

其他厂商同格式(文献佐证):
    Leica   SLLens01.plf / SLLens09.plf / 2870_11.plf
    Samyang 7801V340.plf  (AF 35-150/2-2.8 L)

注意:固件二进制不入库(.gitignore 已排除 *.plf)。
"""
import os
import sys
import urllib.request

FILES = {
    'S02D0120.plf': 'S02D0120_sigma_14F14_art.plf',
    'A0040140.plf': 'A0040140_sigma_30F14_cont.plf',
    'S02A0130.plf': 'S02A0130_sigma_50F2_cont.plf',
}
BASE = 'https://www.sigma-global.com/en/support/download/'
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'firmware', 'sigma')


def main():
    os.makedirs(OUT, exist_ok=True)
    for remote, local in FILES.items():
        dst = os.path.join(OUT, local)
        if os.path.exists(dst):
            print(f'  已存在  {local}  ({os.path.getsize(dst):,} B)')
            continue
        url = BASE + remote
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Referer': 'https://www.sigma-global.com/en/support/firmware/',
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as r, open(dst, 'wb') as f:
                f.write(r.read())
            with open(dst, 'rb') as f:
                magic = f.read(21)
            print(f'  OK      {local}  ({os.path.getsize(dst):,} B)  magic={magic!r}')
        except Exception as e:
            print(f'  ERR     {url}: {e}')


if __name__ == '__main__':
    sys.exit(main())
