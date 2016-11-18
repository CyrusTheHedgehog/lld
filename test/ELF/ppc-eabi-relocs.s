# RUN: llvm-mc -filetype=obj -triple=powerpc-unknown-unknown-eabi %s -o %t
# RUN: ld.lld %t -o %t2
# RUN: llvm-objdump -disassemble-all %t2 | FileCheck %s
# REQUIRES: ppc

.sdata2
smallstr2:
  .long 0xDEADD00D
  .long 0xABCDEFAB

# CHECK: Disassembly of section .sdata2:
# CHECK: smallstr2:
# CHECK:    100d4:	de ad d0 0d 	stfdu 21, -12275(13)
# CHECK:    100d8:	ab cd ef ab 	lha 30, -4181(13)

.section .R_PPC_EMB_SDA21,"ax",@progbits
  lis 13, _SDA_BASE_@ha
  ori 13, 13, _SDA_BASE_@l
  lis 2, _SDA2_BASE_@ha
  ori 2, 2, _SDA2_BASE_@l
  lwz 4, smallstr@sda21(0)
  lwz 5, smallstr2@sda21(0)

# CHECK: Disassembly of section .R_PPC_EMB_SDA21:
# CHECK: .R_PPC_EMB_SDA21:
# CHECK: 11000:	3d a0 00 01 	lis 13, 1
# CHECK: 11004:	61 ad 20 04 	ori 13, 13, 8196
# CHECK: 11008:	3c 40 00 01 	lis 2, 1
# CHECK: 1100c:	60 42 00 d8 	ori 2, 2, 216
# CHECK: 11010:	80 8d 00 00 	lwz 4, 0(13)
# CHECK: 11014:	80 a2 ff fc 	lwz 5, -4(2)

.sdata
  .long 0xABCDEFAB
smallstr:
  .long 0xDEADBEEF

# CHECK: Disassembly of section .sdata:
# CHECK: .sdata:
# CHECK:    12000:	ab cd ef ab 	lha 30, -4181(13)
# CHECK: smallstr:
# CHECK:    12004:	de ad be ef 	stfdu 21, -16657(13)
