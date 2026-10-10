# 最大共享函数 指纹=5ba6c9099252ca2c 93 insn 样本=4001 @0x0328B8
# 出现在 6/6 个型号: 4001@0x0328B8, 4002@0x036718, 4003@0x006ED8, 4006@0x021F88, 400C@0x008AAC, 400E@0x008ADC

  0x0328B8  f0b5       push      {r4, r5, r6, r7, lr}
  0x0328BA  40f2ff75   movw      r5, #0x7ff
  0x0328BE  81ea030c   eor.w     ip, r1, r3
  0x0328C2  0cf0004c   and       ip, ip, #0x80000000
  0x0328C6  15ea1154   ands.w    r4, r5, r1, lsr #20
  0x0328CA  1dbf       ittte     ne
  0x0328CC  15ea1357   ands.w    r7, r5, r3, lsr #20
  0x0328D0  ac42       cmp       r4, r5
  0x0328D2  af42       cmp       r7, r5
  0x0328D4  e5e0       b         #0x32aa2
  0x0328D6  bc41       sbcs      r4, r7
  0x0328D8  c1f31301   ubfx      r1, r1, #0, #0x14
  0x0328DC  c3f31303   ubfx      r3, r3, #0, #0x14
  0x0328E0  801a       subs      r0, r0, r2
  0x0328E2  9941       sbcs      r1, r3
  0x0328E4  43f48013   orr       r3, r3, #0x100000
  0x0328E8  04d2       bhs       #0x328f4
  0x0328EA  641e       subs      r4, r4, #1
  0x0328EC  4000       lsls      r0, r0, #1
  0x0328EE  4941       adcs      r1, r1
  0x0328F0  8018       adds      r0, r0, r2
  0x0328F2  5941       adcs      r1, r3
  0x0328F4  c902       lsls      r1, r1, #0xb
  0x0328F6  41ea5051   orr.w     r1, r1, r0, lsr #21
  0x0328FA  b1fbf3f6   udiv      r6, r1, r3
  0x0328FE  03fb1611   mls       r1, r3, r6, r1
  0x032902  a2fb0675   umull     r7, r5, r2, r6
  0x032906  d7ebc020   rsbs      r0, r7, r0, lsl #11
  0x03290A  a941       sbcs      r1, r5
  0x03290C  02d2       bhs       #0x32914
  0x03290E  761e       subs      r6, r6, #1
  0x032910  8018       adds      r0, r0, r2
  0x032912  5941       adcs      r1, r3
  0x032914  c902       lsls      r1, r1, #0xb
  0x032916  41ea5051   orr.w     r1, r1, r0, lsr #21
  0x03291A  b1fbf3fe   udiv      lr, r1, r3
  0x03291E  03fb1e11   mls       r1, r3, lr, r1
  0x032922  a2fb0e75   umull     r7, r5, r2, lr
  0x032926  d7ebc020   rsbs      r0, r7, r0, lsl #11
  0x03292A  a941       sbcs      r1, r5
  0x03292C  03d2       bhs       #0x32936
  0x03292E  aef1010e   sub.w     lr, lr, #1
  0x032932  8018       adds      r0, r0, r2
  0x032934  5941       adcs      r1, r3
  0x032936  8902       lsls      r1, r1, #0xa
  0x032938  41ea9051   orr.w     r1, r1, r0, lsr #22
  0x03293C  7605       lsls      r6, r6, #0x15
  0x03293E  46ea8e2e   orr.w     lr, r6, lr, lsl #10
  0x032942  b1fbf3f6   udiv      r6, r1, r3
  0x032946  03fb1611   mls       r1, r3, r6, r1
  0x03294A  a2fb0675   umull     r7, r5, r2, r6
  0x03294E  d7eb8020   rsbs      r0, r7, r0, lsl #10
  0x032952  a941       sbcs      r1, r5
  0x032954  02d2       bhs       #0x3295c
  0x032956  761e       subs      r6, r6, #1
  0x032958  8018       adds      r0, r0, r2
  0x03295A  5941       adcs      r1, r3
  0x03295C  c902       lsls      r1, r1, #0xb
  0x03295E  41ea5051   orr.w     r1, r1, r0, lsr #21
  0x032962  4eea060e   orr.w     lr, lr, r6
  0x032966  b1fbf3f6   udiv      r6, r1, r3
  0x03296A  03fb1611   mls       r1, r3, r6, r1
  0x03296E  a2fb0675   umull     r7, r5, r2, r6
  0x032972  d7ebc020   rsbs      r0, r7, r0, lsl #11
  0x032976  a941       sbcs      r1, r5
  0x032978  02d2       bhs       #0x32980
  0x03297A  761e       subs      r6, r6, #1
  0x03297C  8018       adds      r0, r0, r2
  0x03297E  5941       adcs      r1, r3
  0x032980  c902       lsls      r1, r1, #0xb
  0x032982  41ea5051   orr.w     r1, r1, r0, lsr #21
  0x032986  b1fbf3f7   udiv      r7, r1, r3
  0x03298A  03fb1711   mls       r1, r3, r7, r1
  0x03298E  a2fb0735   umull     r3, r5, r2, r7
  0x032992  d3ebc020   rsbs      r0, r3, r0, lsl #11
  0x032996  a941       sbcs      r1, r5
  0x032998  67f10007   sbc       r7, r7, #0
  0x03299C  0cbf       ite       eq
  0x03299E  0042       tst       r0, r0
  0x0329A0  47f00107   orr       r7, r7, #1
  0x0329A4  66f3d527   bfi       r7, r6, #0xb, #0xb
  0x0329A8  4fea1e31   lsr.w     r1, lr, #0xc
  0x0329AC  b808       lsrs      r0, r7, #2
  0x0329AE  14f58064   adds.w    r4, r4, #0x400
  0x0329B2  12dd       ble       #0x329da
  0x0329B4  bd07       lsls      r5, r7, #0x1e
  0x0329B6  75f10042   sbcs      r2, r5, #-0x80000000
  0x0329BA  50eb0e50   adcs.w    r0, r0, lr, lsl #20
  0x0329BE  51eb0451   adcs.w    r1, r1, r4, lsl #20
  0x0329C2  11f5801f   cmn.w     r1, #0x100000
  0x0329C6  5cbf       itt       pl
  0x0329C8  41ea0c01   orr.w     r1, r1, ip
  0x0329CC  f0bd       pop       {r4, r5, r6, r7, pc}
