import os
import re
import struct
from collections import Counter

FW = r'firmware'
p = os.path.join(FW, '4001V020.plf')
d = open(p, 'rb').read()
n = len(d)
OUT = r'.\work\lens_disasm.txt'

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

lines = []
def out(s=''):
    print(s)
    lines.append(s)

out(f'=== 4001V020.plf 鍙嶆眹缂栧垎鏋?({n:,} B) ===')

# 1) 鎵?ARM Cortex-M 鍚戦噺琛?杩炵画 word 涓?鑻ュ共鎸囧悜"浠ｇ爜鍖轰笖 bit0=1"(Thumb 鍏ュ彛)
out()
out('=== 1) Cortex-M 鍚戦噺琛ㄥ€欓€?杩炵画 4 瀛楄妭,鍊艰惤鍦ㄦ枃浠跺唴涓?bit0=1)===')
cand = []
for off in range(0, n - 64, 4):
    vals = struct.unpack_from('<16I', d, off)
    # 鍚戦噺琛ㄧ壒寰?绗?2 涓捣澶氫负濂囨暟(Thumb),涓旈兘鍦ㄨ寖鍥村唴
    odd = sum(1 for v in vals[1:8] if v & 1 and 0x1000 <= (v & ~1) < n)
    if odd >= 6:
        cand.append((off, vals[:8], odd))
for off, vals, odd in cand[:5]:
    out(f'  @0x{off:06X} (odd={odd}): ' + ' '.join(f'0x{v:08X}' for v in vals))
if not cand:
    out('  (鏈壘鍒板吀鍨嬪悜閲忚〃 鈥斺€?鍙兘浠ｇ爜涓嶆槸浠庢枃浠跺亸绉?0 鍔犺浇)')

# 2) 缁熻浠ｇ爜鍖?鏈夋晥 Thumb 鎸囦护瀵嗗害),杈撳嚭鍒嗗尯
out()
out('=== 2) 浠ｇ爜/鏁版嵁鍒嗗尯(0x1000 绐楀彛:鏈夋晥鎸囦护姣?===')
W = 0x1000
prev = None
segs = []
for off in range(0, n, W):
    seg = d[off:off + W]
    cnt = 0
    for _ in md.disasm(seg, off):
        cnt += 1
    ratio = cnt / (W / 2)
    kind = 'code' if ratio > 0.5 else ('mixed' if ratio > 0.2 else 'data')
    segs.append((off, kind, ratio))
    if kind != prev:
        out(f'  @0x{off:06X}  {kind}  (instr_ratio={ratio:.2f})')
        prev = kind

# 3) 鎵惧瓧绗︿覆寮曠敤:LDR literal 鎸囧悜 ASCII 鍖?out()
out('=== 3) 浠ｇ爜涓殑 PC 鐩稿鍔犺浇(LDR literal,鍙兘寮曠敤瀛楃涓?琛?===')
lit_hits = []
addr = 0
while addr < n - 4:
    ins_iter = list(md.disasm(d[addr:addr + 4], addr))
    if ins_iter:
        ins = ins_iter[0]
        if ins.mnemonic in ('ldr.w', 'ldr') and '[pc,' in ins.op_str:
            m = re.search(r'#(0x[0-9a-f]+)', ins.op_str)
            if m:
                target = ins.address + 4 + int(m.group(1), 16)
                if target < n:
                    lit_hits.append((addr, target))
    addr += 2
out(f'  LDR literal 寮曠敤鏁? {len(lit_hits)}')
# 妫€鏌ヨ繖浜涘紩鐢ㄧ洰鏍囨槸鍚︿负 ASCII
ascii_refs = 0
samples = []
for src, tgt in lit_hits[:4000]:
    seg = d[tgt:tgt + 16]
    if sum(1 for x in seg if 32 <= x < 127) >= 10:
        ascii_refs += 1
        if len(samples) < 12:
            s = ''.join(chr(x) if 32 <= x < 127 else '.' for x in d[tgt:tgt + 32])
            samples.append((src, tgt, s))
out(f'  鎸囧悜 ASCII 鐨勫紩鐢? {ascii_refs}')
for src, tgt, s in samples:
    out(f'    0x{src:06X} -> 0x{tgt:06X}  |{s}|')

# 4) 鍙嶆眹缂栦竴娈典唬鐮佸尯,瀛樻枃浠?out()
out('=== 4) 浠ｇ爜鍖?0x039800 鍙嶆眹缂?鍓?80 鏉?===')
top = 0x039800
for i, ins in enumerate(md.disasm(d[top:top + 0x300], top)):
    if i >= 80:
        break
    out(f'  0x{ins.address:06X}  {ins.bytes.hex():<10} {ins.mnemonic:8} {ins.op_str}')

with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print(f'\n[宸插啓鍏?{OUT}, {len(lines)} 琛宂')
