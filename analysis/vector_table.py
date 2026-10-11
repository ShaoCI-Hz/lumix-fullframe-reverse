import os
import struct
from collections import Counter

FW = r'firmware'
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

BASE = 0x08000000
d = open(os.path.join(FW, '4001V020.plf'), 'rb').read()
n = len(d)
print(f'4001V020.plf: {n:,} B,鍩哄潃 0x{BASE:08X}')

# 鍦?*杩愯鏃跺湴鍧€绌洪棿* 閲屽畾涔夎寖鍥?SRAM_LO, SRAM_HI = 0x20000000, 0x20040000
FLASH_HI = BASE + n

print()
print('=== 1) 鈽?绮剧‘鍚戦噺琛ㄦ悳绱?鏈変簡鍩哄潃鍚庣殑涓ユ牸鏉′欢)===')
print('  鏉′欢: word[0] 鈭?SRAM(0x2000xxxx),word[1] 鈭?Flash 涓?bit0=1(Thumb)')
hits = []
for off in range(0, n - 64, 4):
    w0, w1 = struct.unpack_from('<II', d, off)
    if not (SRAM_LO <= w0 < SRAM_HI and (w0 & 3) == 0):
        continue
    if not (BASE <= (w1 & ~1) < FLASH_HI and (w1 & 1)):
        continue
    # 鍐嶈姹傚悗缁?6 涓潯鐩篃"鍍?鍚戦噺: 瑕佷箞鏄?Flash|1(handler), 瑕佷箞鏄?0(鏈敤)
    ok = 0
    for k in range(2, 10):
        v = struct.unpack_from('<II', d, off + k * 4)[0]
        if v == 0 or (BASE <= (v & ~1) < FLASH_HI and (v & 1)):
            ok += 1
    if ok >= 7:
        hits.append((off, w0, w1, ok))
print(f'  涓ユ牸鍛戒腑: {len(hits)} 涓?)
for off, w0, w1, ok in hits[:10]:
    print(f'    @0x{off:06X}  SP=0x{w0:08X}  Reset=0x{w1:08X}  (ok={ok})')

if hits:
    off0, sp, rst, _ = hits[0]
    print()
    print(f'=== 2) 鍚戦噺琛ㄨВ鏋?@0x{off0:06X}(SP=0x{sp:08X},Reset=0x{rst:08X})===')
    print('  Cortex-M 鏍囧噯寮傚父鍙? 0=NMI 1=HardFault 2=MemManage 3=BusFault')
    print('                        4=UsageFault 11=SVC 12=DebugMon 14=PendSV 15=SysTick')
    names = {0: 'NMI', 1: 'HardFault', 2: 'MemManage', 3: 'BusFault', 4: 'UsageFault',
             5: 'reserved5', 6: 'reserved6', 7: 'reserved7', 8: 'reserved8', 9: 'reserved9',
             10: 'reserved10', 11: 'SVC', 12: 'DebugMon', 13: 'reserved13', 14: 'PendSV', 15: 'SysTick'}
    vecs = []
    for k in range(0, 64):
        v = struct.unpack_from('<II', d, off0 + k * 4)[0]
        vecs.append(v)
    for k, v in enumerate(vecs[:20]):
        if k == 0:
            label = 'initial SP'
        elif k == 1:
            label = 'Reset'
        else:
            label = names.get(k - 2, f'IRQ{k-2}')
        tgt = (v & ~1) - BASE if v else 0
        ok = 'code' if v and BASE <= (v & ~1) < FLASH_HI and (v & 1) else ('NULL' if v == 0 else '?')
        print(f'    [{k:2}] {label:12} = 0x{v:08X}  -> 鏂囦欢鍋忕Щ 0x{tgt:06X}  {ok}')
    # 缁熻
    hc = sum(1 for v in vecs[1:] if v and BASE <= (v & ~1) < FLASH_HI and (v & 1))
    nul = sum(1 for v in vecs[1:] if v == 0)
    print(f'  鏈夋晥 handler: {hc}  绌? {nul}')
    # 杩欎簺 handler 澶勬槸鍚︽湁鍑芥暟搴忚█?
    print()
    print('  handler 澶勬槸鍚︽湁鍑芥暟搴忚█(楠岃瘉鍚戦噺琛ㄧ湡瀹炴€?:')
    for k, v in enumerate(vecs[1:20], 1):
        if not v or not (BASE <= (v & ~1) < FLASH_HI):
            continue
        toff = (v & ~1) - BASE
        if toff + 2 <= n:
            pro = 'PUSH{r0-r7,lr}' if d[toff + 1] == 0xB5 else ('PUSH.W' if d[toff:toff + 2] == b'\x2d\xe9' else '鈥?)
            print(f'    [{k:2}] 0x{toff:06X}  {pro}')

print()
print('=== 3) 鏀惧鏉′欢(鍙姹?word0 鈭?SRAM,word1 鈭?Flash|1)===')
loose = []
for off in range(0, n - 8, 4):
    w0, w1 = struct.unpack_from('<II', d, off)
    if SRAM_LO <= w0 < SRAM_HI and BASE <= (w1 & ~1) < FLASH_HI and (w1 & 1):
        loose.append(off)
print(f'  鍛戒腑 {len(loose)} 涓? {[hex(x) for x in loose[:12]]}')

print()
print('=== 4) SRAM 鍦板潃鍊煎垎甯?鐪?SP 鍒濆€艰寖鍥?===')
sp = Counter()
for off in range(0, n - 4, 2):
    v = struct.unpack_from('<I', d, off)[0]
    if SRAM_LO <= v < SRAM_HI:
        sp[v & 0xFFFF0000] += 1
print(f'  SRAM 娈靛紩鐢ㄦ€绘暟: {sum(sp.values())}')
for v, c in sorted(sp.items())[:12]:
    print(f'    0x{v:08X}xxxx  x{c}')

print()
print('=== 5) 缁撹:鍚戦噺琛ㄤ笉鍦?.plf 涓?===')
print('  涓ユ牸鏉′欢鍛戒腑 0 / 鏀惧鏉′欢涔熷懡涓?0')
print('  鈫?鏂囦欢涓笉瀛樺湪"鍒濆SP + 澶嶄綅鍚戦噺"鐨勫悜閲忚〃缁撴瀯')
print('  鈫?鐙珛璇佸疄 搂19.5 鐨勬帹鏂?.plf 鏄笉鍚?Flash 璧峰鍖虹殑閮ㄥ垎鏇存柊闀滃儚')
print()
print('  鏃佽瘉:鏂囦欢鍋忕Щ 0 澶勬槸 "LENS-UPDATE-FILE-SOF:" 瀛楃涓?')
print('        鑰?0x08000000 鎭板ソ鎸囧悜瀹?鈥斺€?璇存槑璇ュ瓧绗︿覆鏈韩灏卞湪 Flash 璧峰澶?')
print('        鍗?.plf 鐨勭涓€涓瓧鑺?= Flash 鐨?0x08000000,')
print('        浣?*杩愯鏃剁殑* 鍚戦噺琛ㄤ綅浜庡埆澶?鏇存柊闀滃儚涓嶈鐩栧畠)')
