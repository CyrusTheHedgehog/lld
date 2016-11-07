# RUN: llvm-mc -filetype=obj -triple=powerpc-unknown-freebsd %s -o %t
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

.section .R_PPC_ADDR16_HA,"ax",@progbits
.globl _start
_start:
  lis 4, msg@ha
msg:
  .string "foo"
  len = . - msg

# CHECK: Disassembly of section .R_PPC_ADDR16_HA:
# CHECK: _start:
# CHECK:    11000:       3c 80 00 01     lis 4, 1
# CHECK: msg:
# CHECK:    11004:       66 6f 6f 00     oris 15, 19, 28416

.section .R_PPC_ADDR16_LO,"ax",@progbits
  addi 4, 4, msg@l
mystr:
  .asciz "blah"
  len = . - mystr

# CHECK: Disassembly of section .R_PPC_ADDR16_LO:
# CHECK: .R_PPC_ADDR16_LO:
# CHECK:    11008:       38 84 10 04     addi 4, 4, 4100
# CHECK: mystr:
# CHECK:    1100c:       62 6c 61 68     ori 12, 19, 24936

.align  2
.section .R_PPC_REL24,"ax",@progbits
.globl .FR_PPC_REL24
.FR_PPC_REL24:
  b .Lfoox
.section .R_PPC_REL24_2,"ax",@progbits
.Lfoox:

# CHECK: Disassembly of section .R_PPC_REL24:
# CHECK: .FR_PPC_REL24:
# CHECK:    11014:       48 00 00 04     b .+4

.section .R_PPC_REL32,"ax",@progbits
.globl .FR_PPC_REL32
.FR_PPC_REL32:
  .long .Lfoox3 - .
.section .R_PPC_REL32_2,"ax",@progbits
.Lfoox3:

# CHECK: Disassembly of section .R_PPC_REL32:
# CHECK: .FR_PPC_REL32:
# CHECK:    11018:       00 00 00 04

.section .R_PPC_ADDR32,"ax",@progbits
.globl .FR_PPC_ADDR32
.FR_PPC_ADDR32:
  .long .Lfoox2
.section .R_PPC_ADDR32_2,"ax",@progbits
.Lfoox2:

# CHECK: Disassembly of section .R_PPC_ADDR32:
# CHECK: .FR_PPC_ADDR32:
# CHECK:    1101c:       00 01 10 20

.section .R_PPC_EMB_SDA21,"ax",@progbits
  lis 13, _SDA_BASE_@ha
  ori 13, 13, _SDA_BASE_@l
  lis 2, _SDA2_BASE_@ha
  ori 2, 2, _SDA2_BASE_@l
  lwz 4, smallstr@sdarx(0)
  lwz 5, smallstr2@sdarx(0)

# CHECK: Disassembly of section .R_PPC_EMB_SDA21:
# CHECK: .R_PPC_EMB_SDA21:
# CHECK: 11020:	3d a0 00 01 	lis 13, 1
# CHECK: 11024:	61 ad 20 04 	ori 13, 13, 8196
# CHECK: 11028:	3c 40 00 01 	lis 2, 1
# CHECK: 1102c:	60 42 00 d8 	ori 2, 2, 216
# CHECK: 11030:	80 8d 00 00 	lwz 4, 0(13)
# CHECK: 11034:	80 a2 ff fc 	lwz 5, -4(2)

.sdata
  .long 0xABCDEFAB
smallstr:
  .long 0xDEADBEEF

# CHECK: Disassembly of section .sdata:
# CHECK: .sdata:
# CHECK:    12000:	ab cd ef ab 	lha 30, -4181(13)
# CHECK: smallstr:
# CHECK:    12004:	de ad be ef 	stfdu 21, -16657(13)
