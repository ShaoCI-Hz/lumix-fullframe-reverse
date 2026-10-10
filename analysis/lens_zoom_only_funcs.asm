# 变焦组专属函数(定焦型号中完全不存在)
# 这些是最可能的"变焦/镜头特定业务逻辑",而非编译器运行时库


# ==================================================================
# 指纹 9f87c20b6e3a5642  (147 指令)  zoom-only, largest
# 位置: 4001 @0x03E3DC
# ==================================================================
  0x03E3DC  2de9f047   push.w    {r4, r5, r6, r7, r8, sb, sl, lr}
  0x03E3E0  0500       movs      r5, r0
  0x03E3E2  0e00       movs      r6, r1
  0x03E3E4  1700       movs      r7, r2
  0x03E3E6  1c00       movs      r4, r3
  0x03E3E8  5ff0ff31   movs.w    r1, #-1
  0x03E3EC  1320       movs      r0, #0x13
  0x03E3EE  fff7b7fc   bl        #0x3dd60
  0x03E3F2  72b6       cpsid     i
  0x03E3F4  a348       ldr       r0, [pc, #0x28c]
  0x03E3F6  0078       ldrb      r0, [r0]
  0x03E3F8  2842       tst       r0, r5
  0x03E3FA  05d0       beq       #0x3e408
  0x03E3FC  62b6       cpsie     i
  0x03E3FE  1320       movs      r0, #0x13
  0x03E400  fff7b2fc   bl        #0x3dd68
  0x03E404  0620       movs      r0, #6
  0x03E406  5be0       b         #0x3e4c0
  0x03E408  9f48       ldr       r0, [pc, #0x27c]
  0x03E40A  0088       ldrh      r0, [r0]
  0x03E40C  0128       cmp       r0, #1
  0x03E40E  09d0       beq       #0x3e424
  0x03E410  9e48       ldr       r0, [pc, #0x278]
  0x03E412  0078       ldrb      r0, [r0]
  0x03E414  2842       tst       r0, r5
  0x03E416  05d0       beq       #0x3e424
  0x03E418  62b6       cpsie     i
  0x03E41A  1320       movs      r0, #0x13
  0x03E41C  fff7a4fc   bl        #0x3dd68
  0x03E420  0720       movs      r0, #7
  0x03E422  4de0       b         #0x3e4c0
  0x03E424  9a48       ldr       r0, [pc, #0x268]
  0x03E426  90f800c0   ldrb.w    ip, [r0]
  0x03E42A  1cf1010c   adds.w    ip, ip, #1
  0x03E42E  5ffa8cfc   uxtb.w    ip, ip
  0x03E432  bcf1030f   cmp.w     ip, #3
  0x03E436  01db       blt       #0x3e43c
  0x03E438  5ff0000c   movs.w    ip, #0
  0x03E43C  9548       ldr       r0, [pc, #0x254]
  0x03E43E  0078       ldrb      r0, [r0]
  0x03E440  6146       mov       r1, ip
  0x03E442  c9b2       uxtb      r1, r1
  0x03E444  8842       cmp       r0, r1
  0x03E446  05d1       bne       #0x3e454
  0x03E448  62b6       cpsie     i
  0x03E44A  1320       movs      r0, #0x13
  0x03E44C  fff78cfc   bl        #0x3dd68
  0x03E450  0420       movs      r0, #4
  0x03E452  35e0       b         #0x3e4c0
  0x03E454  ddf830e0   ldr.w     lr, [sp, #0x30]
  0x03E458  ddf82c80   ldr.w     r8, [sp, #0x2c]
  0x03E45C  0a98       ldr       r0, [sp, #0x28]
  0x03E45E  0999       ldr       r1, [sp, #0x24]
  0x03E460  089a       ldr       r2, [sp, #0x20]
  0x03E462  dff83492   ldr.w     sb, [pc, #0x234]
  0x03E466  8a4b       ldr       r3, [pc, #0x228]
  0x03E468  93f800a0   ldrb.w    sl, [r3]
  0x03E46C  1423       movs      r3, #0x14
  0x03E46E  03fb0afa   mul       sl, r3, sl
  0x03E472  09eb0a03   add.w     r3, sb, sl
  0x03E476  1d70       strb      r5, [r3]
  0x03E478  b146       mov       sb, r6
  0x03E47A  1ffa89f9   uxth.w    sb, sb
  0x03E47E  5fea1929   lsrs.w    sb, sb, #8
  0x03E482  83f80190   strb.w    sb, [r3, #1]
  0x03E486  9e70       strb      r6, [r3, #2]
  0x03E488  df70       strb      r7, [r3, #3]
  0x03E48A  1c71       strb      r4, [r3, #4]
  0x03E48C  5a71       strb      r2, [r3, #5]
  0x03E48E  0022       movs      r2, #0
  0x03E490  9a71       strb      r2, [r3, #6]
  0x03E492  d971       strb      r1, [r3, #7]
  0x03E494  1872       strb      r0, [r3, #8]
  0x03E496  c3f80c80   str.w     r8, [r3, #0xc]
  0x03E49A  c3f810e0   str.w     lr, [r3, #0x10]
  0x03E49E  7c48       ldr       r0, [pc, #0x1f0]
  0x03E4A0  80f800c0   strb.w    ip, [r0]
  0x03E4A4  7948       ldr       r0, [pc, #0x1e4]
  0x03E4A6  0078       ldrb      r0, [r0]
  0x03E4A8  0543       orrs      r5, r0
  0x03E4AA  7848       ldr       r0, [pc, #0x1e0]
  0x03E4AC  0570       strb      r5, [r0]
  0x03E4AE  62b6       cpsie     i
  0x03E4B0  00f008f8   bl        #0x3e4c4
  0x03E4B4  0400       movs      r4, r0
  0x03E4B6  1320       movs      r0, #0x13
  0x03E4B8  fff756fc   bl        #0x3dd68
  0x03E4BC  2000       movs      r0, r4
  0x03E4BE  40b2       sxtb      r0, r0
  0x03E4C0  bde8f087   pop.w     {r4, r5, r6, r7, r8, sb, sl, pc}
  0x03E4C4  80b5       push      {r7, lr}
  0x03E4C6  72b6       cpsid     i
  0x03E4C8  7448       ldr       r0, [pc, #0x1d0]
  0x03E4CA  0078       ldrb      r0, [r0]
  0x03E4CC  0128       cmp       r0, #1
  0x03E4CE  02d1       bne       #0x3e4d6
  0x03E4D0  62b6       cpsie     i
  0x03E4D2  0220       movs      r0, #2
  0x03E4D4  30e0       b         #0x3e538
  0x03E4D6  6f48       ldr       r0, [pc, #0x1bc]
  0x03E4D8  0078       ldrb      r0, [r0]
  0x03E4DA  6d49       ldr       r1, [pc, #0x1b4]
  0x03E4DC  0978       ldrb      r1, [r1]
  0x03E4DE  8842       cmp       r0, r1
  0x03E4E0  02d1       bne       #0x3e4e8
  0x03E4E2  62b6       cpsie     i
  0x03E4E4  0520       movs      r0, #5
  0x03E4E6  27e0       b         #0x3e538
  0x03E4E8  6b49       ldr       r1, [pc, #0x1ac]
  0x03E4EA  6a48       ldr       r0, [pc, #0x1a8]
  0x03E4EC  0278       ldrb      r2, [r0]
  0x03E4EE  1420       movs      r0, #0x14
  0x03E4F0  4243       muls      r2, r0, r2
  0x03E4F2  01eb0200   add.w     r0, r1, r2
  0x03E4F6  6349       ldr       r1, [pc, #0x18c]
  0x03E4F8  0978       ldrb      r1, [r1]
  0x03E4FA  0278       ldrb      r2, [r0]
  0x03E4FC  1142       tst       r1, r2
  0x03E4FE  14d0       beq       #0x3e52a
  0x03E500  6449       ldr       r1, [pc, #0x190]
  0x03E502  0978       ldrb      r1, [r1]
  0x03E504  491c       adds      r1, r1, #1
  0x03E506  634a       ldr       r2, [pc, #0x18c]
  0x03E508  1170       strb      r1, [r2]
  0x03E50A  6249       ldr       r1, [pc, #0x188]
  0x03E50C  0978       ldrb      r1, [r1]
  0x03E50E  0329       cmp       r1, #3
  0x03E510  02db       blt       #0x3e518
  0x03E512  0021       movs      r1, #0
  0x03E514  5f4a       ldr       r2, [pc, #0x17c]
  0x03E516  1170       strb      r1, [r2]
  0x03E518  5c49       ldr       r1, [pc, #0x170]
  0x03E51A  0978       ldrb      r1, [r1]
  0x03E51C  0078       ldrb      r0, [r0]
  0x03E51E  8143       bics      r1, r0
  0x03E520  5a48       ldr       r0, [pc, #0x168]
  0x03E522  0170       strb      r1, [r0]
  0x03E524  62b6       cpsie     i
  0x03E526  0620       movs      r0, #6
  0x03E528  06e0       b         #0x3e538
  0x03E52A  0121       movs      r1, #1
  0x03E52C  5b4a       ldr       r2, [pc, #0x16c]
  0x03E52E  1170       strb      r1, [r2]
  0x03E530  62b6       cpsie     i
  0x03E532  fff7d4fd   bl        #0x3e0de
  0x03E536  0020       movs      r0, #0
  0x03E538  02bd       pop       {r1, pc}

# ==================================================================
# 指纹 8c3b7813e9f73380  (76 指令)  zoom-only
# 位置: 4001 @0x03E244
# ==================================================================
  0x03E244  f8b5       push      {r3, r4, r5, r6, r7, lr}
  0x03E246  0022       movs      r2, #0
  0x03E248  dff81434   ldr.w     r3, [pc, #0x414]
  0x03E24C  1a60       str       r2, [r3]
  0x03E24E  c0b2       uxtb      r0, r0
  0x03E250  0028       cmp       r0, #0
  0x03E252  03d0       beq       #0x3e25c
  0x03E254  49b2       sxtb      r1, r1
  0x03E256  dff80804   ldr.w     r0, [pc, #0x408]
  0x03E25A  0160       str       r1, [r0]
  0x03E25C  dff8b013   ldr.w     r1, [pc, #0x3b0]
  0x03E260  dff8b003   ldr.w     r0, [pc, #0x3b0]
  0x03E264  fbf736fd   bl        #0x39cd4
  0x03E268  0020       movs      r0, #0
  0x03E26A  dff8ac13   ldr.w     r1, [pc, #0x3ac]
  0x03E26E  0870       strb      r0, [r1]
  0x03E270  0120       movs      r0, #1
  0x03E272  dff8e813   ldr.w     r1, [pc, #0x3e8]
  0x03E276  0860       str       r0, [r1]
  0x03E278  dff8ec13   ldr.w     r1, [pc, #0x3ec]
  0x03E27C  03a8       add       r0, sp, #0xc
  0x03E27E  00f054f9   bl        #0x3e52a
  0x03E282  40b2       sxtb      r0, r0
  0x03E284  0328       cmp       r0, #3
  0x03E286  02d1       bne       #0x3e28e
  0x03E288  0020       movs      r0, #0
  0x03E28A  8df80c00   strb.w    r0, [sp, #0xc]
  0x03E28E  9df80c00   ldrb.w    r0, [sp, #0xc]
  0x03E292  0128       cmp       r0, #1
  0x03E294  0dd0       beq       #0x3e2b2
  0x03E296  0228       cmp       r0, #2
  0x03E298  06d0       beq       #0x3e2a8
  0x03E29A  0428       cmp       r0, #4
  0x03E29C  0fd0       beq       #0x3e2be
  0x03E29E  0828       cmp       r0, #8
  0x03E2A0  10d0       beq       #0x3e2c4
  0x03E2A2  1028       cmp       r0, #0x10
  0x03E2A4  1dd0       beq       #0x3e2e2
  0x03E2A6  2be0       b         #0x3e300
  0x03E2A8  8021       movs      r1, #0x80
  0x03E2AA  1620       movs      r0, #0x16
  0x03E2AC  fdf714f8   bl        #0x3b2d8
  0x03E2B0  26e0       b         #0x3e300
  0x03E2B2  4ff48071   mov.w     r1, #0x100
  0x03E2B6  1620       movs      r0, #0x16
  0x03E2B8  fdf70ef8   bl        #0x3b2d8
  0x03E2BC  20e0       b         #0x3e300
  0x03E2BE  fdf71ffb   bl        #0x3b900
  0x03E2C2  1de0       b         #0x3e300
  0x03E2C4  dff8a403   ldr.w     r0, [pc, #0x3a4]
  0x03E2C8  0290       str       r0, [sp, #8]
  0x03E2CA  0120       movs      r0, #1
  0x03E2CC  0190       str       r0, [sp, #4]
  0x03E2CE  fd20       movs      r0, #0xfd
  0x03E2D0  0090       str       r0, [sp]
  0x03E2D2  0e23       movs      r3, #0xe
  0x03E2D4  0322       movs      r2, #3
  0x03E2D6  dff89813   ldr.w     r1, [pc, #0x398]
  0x03E2DA  1b20       movs      r0, #0x1b
  0x03E2DC  fcf739ff   bl        #0x3b152
  0x03E2E0  0ee0       b         #0x3e300
  0x03E2E2  dff88803   ldr.w     r0, [pc, #0x388]
  0x03E2E6  0290       str       r0, [sp, #8]
  0x03E2E8  0020       movs      r0, #0
  0x03E2EA  0190       str       r0, [sp, #4]
  0x03E2EC  fd20       movs      r0, #0xfd
  0x03E2EE  0090       str       r0, [sp]
  0x03E2F0  6c23       movs      r3, #0x6c
  0x03E2F2  0322       movs      r2, #3
  0x03E2F4  dff87813   ldr.w     r1, [pc, #0x378]
  0x03E2F8  1b20       movs      r0, #0x1b
  0x03E2FA  fcf72aff   bl        #0x3b152
  0x03E2FE  ffe7       b         #0x3e300
  0x03E300  00f0d8f8   bl        #0x3e4b4
  0x03E304  05b0       add       sp, #0x14
  0x03E306  00bd       pop       {pc}

# ==================================================================
# 指纹 0b5c9767c9ea7872  (76 指令)  zoom-only
# 位置: 4001 @0x05F4EC
# ==================================================================
  0x05F4EC  2de9fe43   push.w    {r1, r2, r3, r4, r5, r6, r7, r8, sb, lr}
  0x05F4F0  0546       mov       r5, r0
  0x05F4F2  0024       movs      r4, #0
  0x05F4F4  0846       mov       r0, r1
  0x05F4F6  002a       cmp       r2, #0
  0x05F4F8  04d1       bne       #0x5f504
  0x05F4FA  5d1b       subs      r5, r3, r5
  0x05F4FC  0028       cmp       r0, #0
  0x05F4FE  05d5       bpl       #0x5f50c
  0x05F500  4d19       adds      r5, r1, r5
  0x05F502  03e0       b         #0x5f50c
  0x05F504  ed18       adds      r5, r5, r3
  0x05F506  0028       cmp       r0, #0
  0x05F508  00d4       bmi       #0x5f50c
  0x05F50A  4d19       adds      r5, r1, r5
  0x05F50C  9df92c60   ldrsb.w   r6, [sp, #0x2c]
  0x05F510  0a9f       ldr       r7, [sp, #0x28]
  0x05F512  c918       adds      r1, r1, r3
  0x05F514  8946       mov       sb, r1
  0x05F516  07f10c01   add.w     r1, r7, #0xc
  0x05F51A  81b0       sub       sp, #4
  0x05F51C  6846       mov       r0, sp
  0x05F51E  0c22       movs      r2, #0xc
  0x05F520  dcf78efe   bl        #0x3c240
  0x05F524  08bc       pop       {r3}
  0x05F526  b7f90420   ldrsh.w   r2, [r7, #4]
  0x05F52A  3146       mov       r1, r6
  0x05F52C  2846       mov       r0, r5
  0x05F52E  00b2       sxth      r0, r0
  0x05F530  00f099fe   bl        #0x60266
  0x05F534  8046       mov       r8, r0
  0x05F536  07f10c01   add.w     r1, r7, #0xc
  0x05F53A  81b0       sub       sp, #4
  0x05F53C  6846       mov       r0, sp
  0x05F53E  0c22       movs      r2, #0xc
  0x05F540  dcf77efe   bl        #0x3c240
  0x05F544  08bc       pop       {r3}
  0x05F546  b7f90420   ldrsh.w   r2, [r7, #4]
  0x05F54A  3146       mov       r1, r6
  0x05F54C  4846       mov       r0, sb
  0x05F54E  00b2       sxth      r0, r0
  0x05F550  00f089fe   bl        #0x60266
  0x05F554  2db2       sxth      r5, r5
  0x05F556  4545       cmp       r5, r8
  0x05F558  03d1       bne       #0x5f562
  0x05F55A  0ffa89f9   sxth.w    sb, sb
  0x05F55E  8145       cmp       sb, r0
  0x05F560  00d0       beq       #0x5f564
  0x05F562  0224       movs      r4, #2
  0x05F564  2046       mov       r0, r4
  0x05F566  bde8fe83   pop.w     {r1, r2, r3, r4, r5, r6, r7, r8, sb, pc}
  0x05F56A  38b5       push      {r3, r4, r5, lr}
  0x05F56C  0546       mov       r5, r0
  0x05F56E  0c46       mov       r4, r1
  0x05F570  1146       mov       r1, r2
  0x05F572  0920       movs      r0, #9
  0x05F574  00f018ff   bl        #0x603a8
  0x05F578  dff88c18   ldr.w     r1, [pc, #0x88c]
  0x05F57C  95f9c220   ldrsb.w   r2, [r5, #0xc2]
  0x05F580  02ebc203   add.w     r3, r2, r2, lsl #3
  0x05F584  01eb4301   add.w     r1, r1, r3, lsl #1
  0x05F588  c988       ldrh      r1, [r1, #6]
  0x05F58A  b0fbf1f1   udiv      r1, r0, r1
  0x05F58E  b4f93e20   ldrsh.w   r2, [r4, #0x3e]
  0x05F592  002a       cmp       r2, #0
  0x05F594  01d5       bpl       #0x5f59a
  0x05F596  5242       rsbs      r2, r2, #0
  0x05F598  00e0       b         #0x5f59c
  0x05F59A  92b2       uxth      r2, r2
  0x05F59C  89b2       uxth      r1, r1
  0x05F59E  92b2       uxth      r2, r2
  0x05F5A0  9142       cmp       r1, r2
  0x05F5A2  8041       sbcs      r0, r0
  0x05F5A4  c00f       lsrs      r0, r0, #0x1f
  0x05F5A6  40b2       sxtb      r0, r0
  0x05F5A8  32bd       pop       {r1, r4, r5, pc}

# 20 个"仅变焦组有"的函数清单(按规模)
  9f87c20b6e3a5642   147 insn
  8c3b7813e9f73380    76 insn
  0b5c9767c9ea7872    76 insn
  3eccb866cefcf4ad    64 insn
  7e2df981dde770cd    63 insn
  a35d9176b69ddac3    57 insn
  36a33adb8b8bcfd4    57 insn
  2bb0271244c92c0c    52 insn
  547c5da2a87ac849    51 insn
  371873aef844b6bb    43 insn
  b61112411f2a1273    34 insn
  547b7972269b142a    32 insn