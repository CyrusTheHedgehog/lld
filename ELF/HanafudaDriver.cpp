//===- HanafudaDriver.cpp -------------------------------------------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Driver.h"
#include "Config.h"
#include "Error.h"
#include "ICF.h"
#include "InputFiles.h"
#include "InputSection.h"
#include "LinkerScript.h"
#include "Memory.h"
#include "OutputSections.h"
#include "Strings.h"
#include "SymbolTable.h"
#include "Target.h"
#include "Writer.h"
#include "lld/Config/Version.h"
#include "lld/Driver/Driver.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include <cstdlib>
#include <utility>
#include <unordered_map>

using namespace llvm;
using namespace llvm::ELF;
using namespace llvm::object;
using namespace llvm::sys;
using namespace llvm::support::endian;

using namespace lld;
using namespace lld::elf;

namespace lld {
namespace hanafuda {

class LinkerDriver;

/// Maintains structural information about loaded base file
/// and template for outputting a new file.
///
/// Capable of resolving original data pointers based on
/// VAs (runtime addresses) loaded from the symbol list.
///
/// The constructor will try detecting if the DOL's section
/// layout is consistent with the linker script used with
/// games built with the official Dolphin SDK:
/// * T: .init
/// * D: .extab
/// * D: .extabinit
/// * T: .text
/// * D: .ctors
/// * D: .dtors
/// * D: .rodata
/// * D: .data
/// * B: .bss
/// * D: .sdata+sbss (optional)
/// * D: .sdata2+sbss2 (optional)
///
/// When generating a patched DOL, an additional text and data
/// section is appended to store additional binary components
/// while not disturbing existing VAs. Due to this, additional
/// .bss input sections will be relocated into the patching
/// .data section with a zeroed-out buffer.
class DOLFile {
  MemoryBufferRef MB;
public:
  struct Section {
    uint32_t Offset = 0;
    uint32_t Addr = 0;
    uint32_t Length = 0;
  };
private:
  struct Header {
    uint32_t TextOffs[7];
    uint32_t DataOffs[11];
    uint32_t TextLoads[7];
    uint32_t DataLoads[11];
    uint32_t TextSizes[7];
    uint32_t DataSizes[11];
    uint32_t BssAddr;
    uint32_t BssSize;
    uint32_t EntryPoint;

    void swapBig() {
      if (IsLittleEndianHost)
      {
        for (int i = 0; i < 7; ++i)
          TextOffs[i] = SwapByteOrder_32(TextOffs[i]);
        for (int i = 0; i < 11; ++i)
          DataOffs[i] = SwapByteOrder_32(DataOffs[i]);
        for (int i = 0; i < 7; ++i)
          TextLoads[i] = SwapByteOrder_32(TextLoads[i]);
        for (int i = 0; i < 11; ++i)
          DataLoads[i] = SwapByteOrder_32(DataLoads[i]);
        for (int i = 0; i < 7; ++i)
          TextSizes[i] = SwapByteOrder_32(TextSizes[i]);
        for (int i = 0; i < 11; ++i)
          DataSizes[i] = SwapByteOrder_32(DataSizes[i]);
        BssAddr = SwapByteOrder_32(BssAddr);
        BssSize = SwapByteOrder_32(BssSize);
        EntryPoint = SwapByteOrder_32(EntryPoint);
      }
    }
  };
  Section Texts[7] = {};
  Section Datas[11] = {};
  uint32_t BssAddr = 0;
  uint32_t BssSize = 0;
  uint32_t EntryPoint = 0;
  uint32_t StackBase = 0;
  uint32_t StackEnd = 0;
  uint32_t SdataBase = 0;
  uint32_t Sdata2Base = 0;
  uint32_t ArenaLo = 0;
  bool DolphinSections = false;

  static void BufOverflowErr(uint32_t Offset, uint32_t Size) {
    std::string TheStr;
    raw_string_ostream Str(TheStr);
    Str <<  format("patch out of bounds [%u/%u] bytes", Offset, Size);
    error(Str.str());
  }

  struct Relocation {
    uint32_t Addr;
    uint32_t Offset;
    uint32_t Type;

    void patch(MemoryBufferRef MB, uint32_t Val) const {
      const uint32_t BufSz = MB.getBuffer().size();
      if (Offset >= BufSz) {
        BufOverflowErr(Offset, BufSz);
        return;
      }
      const uint8_t *Ptr = MB.getBuffer().bytes_begin() + Offset;
      uint32_t ActualType;
      if (Type == R_PPC_ADDR16_HA || Type == R_PPC_ADDR16_HI)
        ActualType = ((Val & 0xffff) >= 0x8000) ? R_PPC_ADDR16_HA : R_PPC_ADDR16_HI;
      else
        ActualType = Type;

      uint32_t OldVal;
      if (Config->Verbose) {
        if ((Type - R_PPC_ADDR16) <= 3)
          OldVal = read16be(Ptr);
        else
          OldVal = read32be(Ptr);
      }

      elf::Target->relocateOne(const_cast<uint8_t *>(Ptr), ActualType, Val);

      if (Config->Verbose) {
        uint32_t NewVal;
        const char *FmtStr;
        if ((Type - R_PPC_ADDR16) <= 3) {
          NewVal = read16be(Ptr);
          FmtStr = "Patched 0x%08X(0x%08X) from 0x%04X to 0x%04X as %s\n";
        } else {
          NewVal = read32be(Ptr);
          FmtStr = "Patched 0x%08X(0x%08X) from 0x%08X to 0x%08X as %s\n";
        }
        outs() << format(FmtStr, Addr, Offset, OldVal, NewVal,
                         elf::toString(ActualType).c_str());
      }
    }
  };

  struct RelocationPair {
    Relocation Hi, Lo;

    void patch(MemoryBufferRef MB, uint32_t Val) const {
      Hi.patch(MB, Val);
      Lo.patch(MB, Val);
    }
  };

  llvm::SmallVector<RelocationPair, 5> StackBaseRels;
  llvm::SmallVector<RelocationPair, 5> StackEndRels;
  llvm::SmallVector<RelocationPair, 5> ArenaLoRels;

  // {call-target-addr, Relocation}
  std::unordered_multimap<uint32_t, Relocation>
      OrigCallAddrToInstFileOffs;
  void scanForRelocations(LinkerDriver &Drv);

public:
  DOLFile(MemoryBufferRef M, LinkerDriver &Drv) : MB(M) {
    Header head = *reinterpret_cast<const Header*>(M.getBufferStart());
    head.swapBig();

    int i;
    for (i = 0; i < 7; ++i) {
      if (head.TextOffs[i]) {
        Section& sec = Texts[i];
        sec.Offset = head.TextOffs[i];
        sec.Addr = head.TextLoads[i];
        sec.Length = head.TextSizes[i];
      }
    }

    int j;
    for (j = 0; j < 11; ++j) {
      if (head.DataOffs[j]) {
        Section& sec = Datas[j];
        sec.Offset = head.DataOffs[j];
        sec.Addr = head.DataLoads[j];
        sec.Length = head.DataSizes[j];
      }
    }

    if (i >= 2 && j >= 6)
      DolphinSections = true;

    BssAddr = head.BssAddr;
    BssSize = head.BssSize;
    EntryPoint = head.EntryPoint;

    scanForRelocations(Drv);
  }

  int getTextSectionCount() const {
    for (int i = 0; i < 7; ++i)
      if (!Texts[i].Offset)
        return i;
    return 7;
  }

  int getDataSectionCount() const {
    for (int i = 0; i < 11; ++i)
      if (!Datas[i].Offset)
        return i;
    return 11;
  }

  int getUnusedTextSectionIndex() const {
    for (int i = 0; i < 7; ++i)
      if (!Texts[i].Offset)
        return i;
    return -1;
  }

  int getUnusedDataSectionIndex() const {
    for (int i = 0; i < 11; ++i)
      if (!Datas[i].Offset)
        return i;
    return -1;
  }

  const Section& getTextSection(int index) const { return Texts[index]; }
  const Section& getDataSection(int index) const { return Datas[index]; }
  Section& getTextSection(int index) { return Texts[index]; }
  Section& getDataSection(int index) { return Datas[index]; }

  uint32_t getUnallocatedFileOffset() const {
    uint32_t Offset = 0;
    for (int i = 0; i < 7; ++i) {
      const Section& sec = getTextSection(i);
      Offset = std::max(Offset, sec.Offset + sec.Length);
    }
    for (int i = 0; i < 11; ++i) {
      const Section& sec = getDataSection(i);
      Offset = std::max(Offset, sec.Offset + sec.Length);
    }
    return (Offset + 31) & ~31;
  }

  uint32_t getUnallocatedAddressOffset() const {
    uint32_t Offset = 0;
    for (int i = 0; i < 7; ++i) {
      const Section& sec = getTextSection(i);
      Offset = std::max(Offset, sec.Addr + sec.Length);
    }
    for (int i = 0; i < 11; ++i) {
      const Section& sec = getDataSection(i);
      Offset = std::max(Offset, sec.Addr + sec.Length);
    }
    return (Offset + 31) & ~31;
  }

  StringRef _getTextSectionData(int index) const {
    const Section& sec = getTextSection(index);
    if (!sec.Offset)
      return {};
    return MB.getBuffer().substr(sec.Offset, sec.Length);
  }

  StringRef _getDataSectionData(int index) const {
    const Section& sec = getDataSection(index);
    if (!sec.Offset)
      return {};
    return MB.getBuffer().substr(sec.Offset, sec.Length);
  }

  StringRef getInitSectionData() const {
    if (!DolphinSections)
      return {};
    return _getTextSectionData(0);
  }

  StringRef getExtabSectionData() const {
    if (!DolphinSections)
      return {};
    return _getDataSectionData(0);
  }

  StringRef getExtabInitSectionData() const {
    if (!DolphinSections)
      return {};
    return _getDataSectionData(1);
  }

  StringRef getTextSectionData() const {
    if (!DolphinSections)
      return _getTextSectionData(0);
    return _getTextSectionData(1);
  }

  StringRef getCtorsSectionData() const {
    if (!DolphinSections)
      return {};
    return _getDataSectionData(2);
  }

  StringRef getDtorsSectionData() const {
    if (!DolphinSections)
      return {};
    return _getDataSectionData(3);
  }

  StringRef getRoDataSectionData() const {
    if (!DolphinSections)
      return {};
    return _getDataSectionData(4);
  }

  StringRef getDataSectionData() const {
    if (!DolphinSections)
      return _getDataSectionData(0);
    return _getDataSectionData(5);
  }

  StringRef getSDataSectionData() const {
    if (!DolphinSections)
      return {};
    return _getDataSectionData(6);
  }

  StringRef getSData2SectionData() const {
    if (!DolphinSections)
      return {};
    return _getDataSectionData(7);
  }

  uint32_t getStackBase() const { return StackBase; }
  uint32_t getStackEnd() const { return StackEnd; }
  uint32_t getSdataBase() const { return SdataBase; }
  uint32_t getSdata2Base() const { return Sdata2Base; }
  uint32_t getArenaLo() const { return ArenaLo; }

  bool validateSymbolAddr(uint32_t addr, HanafudaSecType& secOut, int& secIdxOut) const {
    for (int i = 0; i < 7; ++i) {
      const Section& sec = getTextSection(i);
      if (addr >= sec.Addr && addr < (sec.Addr + sec.Length)) {
        secOut = HanafudaSecType::Text;
        secIdxOut = i;
        return false;
      }
    }
    for (int i = 0; i < 11; ++i) {
      const Section& sec = getDataSection(i);
      if (addr >= sec.Addr && addr < (sec.Addr + sec.Length)) {
        secOut = HanafudaSecType::Data;
        secIdxOut = i;
        return false;
      }
    }
    if (addr >= BssAddr && addr < (BssAddr + BssSize)) {
      secOut = HanafudaSecType::Bss;
      return false;
    }
    return true;
  }

  const char* resolveVAData(uint32_t addr) const {
    for (int i = 0; i < 7; ++i) {
      const Section& sec = getTextSection(i);
      if (addr >= sec.Addr && addr < (sec.Addr + sec.Length)) {
        return MB.getBuffer().data() + sec.Offset + (addr - sec.Addr);
      }
    }
    for (int i = 0; i < 11; ++i) {
      const Section& sec = getDataSection(i);
      if (addr >= sec.Addr && addr < (sec.Addr + sec.Length)) {
        return MB.getBuffer().data() + sec.Offset + (addr - sec.Addr);
      }
    }
    return nullptr;
  }

  void patchTargetAddressRelocations(uint32_t oldAddr, uint32_t newAddr);

  void patchForGrowDelta(uint32_t Delta) {
    StackBase += Delta;
    StackEnd += Delta;
    ArenaLo += Delta;
    if (Config->Verbose)
      outs() << "Patching _stack_base_\n";
    for (const RelocationPair &Rel : StackBaseRels)
      Rel.patch(MB, StackBase);
    if (Config->Verbose)
      outs() << "Patching _stack_end_\n";
    for (const RelocationPair &Rel : StackEndRels)
      Rel.patch(MB, StackEnd);
    if (Config->Verbose)
      outs() << "Patching __ArenaLo\n";
    for (const RelocationPair &Rel : ArenaLoRels)
      Rel.patch(MB, ArenaLo);
  }

  void writeTo(uint8_t *BufData) const {
    Header SwappedHead = {};
    SwappedHead.BssAddr = BssAddr;
    SwappedHead.BssSize = BssSize;
    SwappedHead.EntryPoint = EntryPoint;

    for (int i = 0; i < 7; ++i) {
      const Section& sec = getTextSection(i);
      if (!sec.Offset)
        continue;
      SwappedHead.TextOffs[i] = sec.Offset;
      SwappedHead.TextLoads[i] = sec.Addr;
      SwappedHead.TextSizes[i] = sec.Length;
      memmove(BufData + sec.Offset, _getTextSectionData(i).data(), sec.Length);
    }

    for (int i = 0; i < 11; ++i) {
      const Section& sec = getDataSection(i);
      if (!sec.Offset)
        continue;
      SwappedHead.DataOffs[i] = sec.Offset;
      SwappedHead.DataLoads[i] = sec.Addr;
      SwappedHead.DataSizes[i] = sec.Length;
      memmove(BufData + sec.Offset, _getDataSectionData(i).data(), sec.Length);
    }

    SwappedHead.swapBig();
    memmove(BufData, &SwappedHead, sizeof(SwappedHead));
  }
};

class SymbolListFile {
public:
  using ListType = std::vector<std::pair<uint32_t, StringRef>>;
private:
  ListType List;
public:
  SymbolListFile(StringRef S) {
    while (!S.empty()) {
      // Split off each line in the file.
      std::pair<StringRef, StringRef> lineAndRest = S.split('\n');
      StringRef line = lineAndRest.first;
      S = lineAndRest.second;
      S = S.ltrim();

      // Consume address and symbol name
      uint32_t offset;
      if (line.consumeInteger(0, offset))
        continue;
      line = line.ltrim().rtrim();
      if (!line.empty())
        List.emplace_back(offset, line);
    }
  }

  ListType::const_iterator begin() const { return List.cbegin(); }
  ListType::const_iterator end() const { return List.cend(); }
};

class LinkerDriver : public elf::LinkerDriver {
  friend class HanafudaSymbolTable;
  friend class DOLFile;
  Optional<DOLFile> DolFile;

  std::unique_ptr<MCSubtargetInfo> STI;
  std::unique_ptr<MCRegisterInfo> MRI;
  std::unique_ptr<MCAsmInfo> MAI;
  std::unique_ptr<MCInstrInfo> MCII;
  std::unique_ptr<MCContext> Ctx;
  std::unique_ptr<MCDisassembler> DC;
  std::unique_ptr<MCCodeEmitter> MCE;

  void link(llvm::opt::InputArgList &Args);
public:
  void main(ArrayRef<const char *> Args, bool CanExitEarly);
};

static uint32_t getPPCRegisterOp(const MCInst &Inst, int idx = 0) {
  for (const MCOperand &op : Inst)
    if (op.isReg() && !(idx--))
      return op.getReg();
  return 0xffffffff;
}

static uint32_t getPPCGprOp(const MCInst &Inst, unsigned R0, int idx = 0) {
  uint32_t Reg = getPPCRegisterOp(Inst, idx);
  if (Reg < R0 || Reg >= (R0 + 32))
    return 0;
  return Reg - R0;
}

static uint32_t getPPCImmediateOp(const MCInst &Inst) {
  for (const MCOperand &op : Inst)
    if (op.isImm())
      return op.getImm();
  return 0xffffffff;
}

static uint32_t getPPCHiImmediateOp(const MCInst &Inst) {
  return getPPCImmediateOp(Inst) << 16;
}

static uint32_t decodeHa(uint32_t In) {
  return (In - 0x8000) & 0xffff0000;
}

static bool isOneOf(const MCInstrDesc &Desc, unsigned K1, unsigned K2) {
  return (Desc.getOpcode() == K1) || (Desc.getOpcode() == K2);
}
template <typename... Ts>
static bool isOneOf(const MCInstrDesc &Desc, unsigned K1, unsigned K2, Ts... Ks) {
  return (Desc.getOpcode() == K1) || isOneOf(Desc, K2, Ks...);
}

void DOLFile::scanForRelocations(LinkerDriver &Drv) {
  struct PPCInfo {
    unsigned R0;
    unsigned R1;
    unsigned R2;
    unsigned R13;

    unsigned BL;
    unsigned BA;
    unsigned LIS;
    unsigned ORI;
    unsigned ADDI;

    unsigned LBZ;
    unsigned LHA;
    unsigned LHZ;
    unsigned LWZ;
    unsigned LFS;
    unsigned LFD;

    PPCInfo(LinkerDriver &Drv) {
      MCRegisterInfo &MRI = *Drv.MRI;
      MCInstrInfo &MCII = *Drv.MCII;

      for (unsigned i = 0; i < MRI.getNumRegs(); ++i) {
        StringRef name(MRI.getName(i));
        if (name == "R0")
          R0 = i;
        if (name == "R1")
          R1 = i;
        else if (name == "R2")
          R2 = i;
        else if (name == "R13")
          R13 = i;
      }

      for (unsigned i = 0; i < MCII.getNumOpcodes(); ++i) {
        StringRef name = MCII.getName(i);
        if (name == "BL")
          BL = i;
        if (name == "BA")
          BA = i;
        else if (name == "LIS")
          LIS = i;
        else if (name == "ORI")
          ORI = i;
        else if (name == "ADDI")
          ADDI = i;
        else if (name == "LBZ")
          LBZ = i;
        else if (name == "LHA")
          LHA = i;
        else if (name == "LHZ")
          LHZ = i;
        else if (name == "LWZ")
          LWZ = i;
        else if (name == "LFS")
          LFS = i;
        else if (name == "LFD")
          LFD = i;
      }
    }

    bool isMemri(const MCInstrDesc &Desc) const {
      return isOneOf(Desc, LBZ, LHA, LHZ, LWZ, LFS, LFD);
    }
  } PPCI(Drv);

  RelocationPair StackEndRel;

  uint64_t Size;
  ArrayRef<uint8_t> Data(reinterpret_cast<const unsigned char*>(
                         MB.getBuffer().data()), MB.getBufferSize());

  // Iterate text sections for disassembly
  for (int s = 0; s < 7; ++s) {
    Section& sec = Texts[s];
    if (!sec.Offset)
      continue;

    // Caches the latest `lis` immediates for 32 GPRs
    class HiCheck {
      uint32_t HC[32] = {};
    public:
      uint32_t get(unsigned Reg) const {
        if (Reg >= 32)
          return false;
        return HC[Reg];
      }
      void set(unsigned Reg, uint32_t Val) {
        if (Reg >= 32)
          return;
        HC[Reg] = Val;
      }
    } HC;

    // Caches the latest `lis` relocations for 32 GPRs
    Relocation TmpHa[32] = {};

    // Disassemble the section
    for (uint32_t Index = 0; Index < sec.Length; Index += Size) {
      uint32_t FileIndex = sec.Offset + Index;
      uint32_t VAIndex = sec.Addr + Index;

      MCDisassembler::DecodeStatus S;
      MCInst Inst;
      S = Drv.DC->getInstruction(Inst, Size, Data.slice(FileIndex), VAIndex,
                                 /*REMOVE*/ nulls(), nulls());
      switch (S) {
      case MCDisassembler::Fail:
        if (Size == 0)
          Size = 1; // skip illegible bytes
        break;

      case MCDisassembler::SoftFail:
        LLVM_FALLTHROUGH;

      case MCDisassembler::Success: {
        const MCInstrDesc &Desc = Drv.MCII->get(Inst.getOpcode());

        if (s == 0) {
          // Scan .init instructions for stack and small data bases
          uint32_t InstReg = getPPCRegisterOp(Inst);
          if (InstReg == PPCI.R1) {
            // Define _stack_base_
            if (Desc.getOpcode() == PPCI.LIS) {
              StackBase = getPPCHiImmediateOp(Inst);
              TmpHa[1] = Relocation{VAIndex + 2, FileIndex + 2, R_PPC_ADDR16_HI};
            } else if (Desc.getOpcode() == PPCI.ORI) {
              StackBase |= getPPCImmediateOp(Inst);
              RelocationPair P = {TmpHa[1],
                                  Relocation{VAIndex + 2, FileIndex + 2, R_PPC_ADDR16_LO}};
              StackBaseRels.emplace_back(P);
            }

          } else if (InstReg == PPCI.R2) {
            // Define _SDA2_BASE_
            if (Desc.getOpcode() == PPCI.LIS)
              Sdata2Base = getPPCHiImmediateOp(Inst);
            else if (Desc.getOpcode() == PPCI.ORI)
              Sdata2Base |= getPPCImmediateOp(Inst);

          } else if (InstReg == PPCI.R13) {
            // Define _SDA_BASE_
            if (Desc.getOpcode() == PPCI.LIS)
              SdataBase = getPPCHiImmediateOp(Inst);
            else if (Desc.getOpcode() == PPCI.ORI)
              SdataBase |= getPPCImmediateOp(Inst);
          }

        } else {
          // Scan remaining sections for system relocations
          if (Desc.getOpcode() == PPCI.LIS) {
            // Set Ha immedtate if within 0x20000 of the program end
            uint32_t Imm = getPPCHiImmediateOp(Inst);
            if ((Imm >> 24) == 0x80 && Imm >= ((StackBase - 0x20000) & 0xffff0000)) {
              unsigned DstReg = getPPCGprOp(Inst, PPCI.R0);
              HC.set(DstReg, Imm);
              TmpHa[DstReg] = Relocation{VAIndex + 2, FileIndex + 2, R_PPC_ADDR16_HI};
            }

          } else if (PPCI.isMemri(Desc)) {
            // Clear out Ha immediate when consumed
            unsigned SrcReg = getPPCGprOp(Inst, PPCI.R0, 1);
            HC.set(SrcReg, 0);

          } else if (Desc.getOpcode() == PPCI.ADDI) {
            // Potential ADDR16 relocation to handle
            unsigned SrcReg = getPPCGprOp(Inst, PPCI.R0, 1);
            if (uint32_t Hi = HC.get(SrcReg)) {
              uint32_t Imm = getPPCImmediateOp(Inst) & 0xffff;
              RelocationPair P = {TmpHa[SrcReg],
                                  Relocation{VAIndex + 2, FileIndex + 2, R_PPC_ADDR16_LO}};
              if (Imm >= 0x8000) {
                Imm |= decodeHa(Hi);
                P.Hi.Type = R_PPC_ADDR16_HA;
              } else
                Imm |= Hi;

              if (Imm == StackBase) {
                // Scan for _stack_base_
                StackBaseRels.emplace_back(P);

              } else if (Imm < StackBase && Imm > (StackBase - 0x20000)) {
                // Scan for _stack_end_
                if (Imm > StackEnd) {
                  StackEndRel = P;
                  StackEnd = Imm;
                }

              } else if (!ArenaLo && Imm > StackBase && (Imm - StackBase) <= 0x2100) {
                // Scan for __ArenaLo
                ArenaLoRels.emplace_back(P);
                ArenaLo = Imm;
              }

              HC.set(SrcReg, 0);
            }
          }
        }

        if (Desc.getOpcode() == PPCI.BL) {
          // Patch bl calls
          uint32_t Imm = getPPCImmediateOp(Inst);
          if (Imm != 0xffffffff) {
            int32_t Addr = SignExtend32(Imm << 2, 24);
            OrigCallAddrToInstFileOffs.insert(std::make_pair(Addr + VAIndex,
              Relocation{VAIndex, FileIndex, R_PPC_REL24}));
          }

        } else if (Desc.getOpcode() == PPCI.BA) {
          // Patch absolute jumps
          uint32_t Imm = getPPCImmediateOp(Inst);
          if (Imm != 0xffffffff) {
            uint32_t Addr = Imm << 2;
            OrigCallAddrToInstFileOffs.insert(std::make_pair(Addr,
              Relocation{VAIndex, FileIndex, R_PPC_ADDR24}));
          }
        }

        break;
      }
      }
    }
  }

  // Relocate best match result for _stack_end_
  if (StackEnd)
    StackEndRels.emplace_back(StackEndRel);
}

void DOLFile::patchTargetAddressRelocations(uint32_t oldAddr, uint32_t newAddr) {
  const uint32_t BufSz = MB.getBuffer().size();
  for (const std::pair<uint32_t, Relocation> &P :
       make_range(OrigCallAddrToInstFileOffs.equal_range(oldAddr))) {
    if (P.second.Offset >= BufSz) {
      BufOverflowErr(P.second.Offset, BufSz);
      continue;
    }

    // Make relocation PC-relative if needed
    int64_t Addr;
    switch (P.second.Type) {
    case R_PPC_REL24:
      Addr = newAddr - int64_t(P.second.Addr);
      break;
    default:
      Addr = newAddr;
      break;
    }

    // Perform relocation as normal
    elf::Target->relocateOne(
      const_cast<uint8_t *>(MB.getBuffer().bytes_begin() + P.second.Offset),
        P.second.Type, Addr);

    if (Config->Verbose)
      outs() << format("Patched 0x%08X(0x%08X) from 0x%08X to 0x%08X as %s\n",
                       P.second.Addr, P.second.Offset, oldAddr, newAddr,
                       elf::toString(P.second.Type).c_str());
  }
}

bool link(ArrayRef<const char *> Args, bool CanExitEarly,
          raw_ostream &Error) {
  ErrorCount = false;
  ErrorOS = &Error;
  Argv0 = Args[0];

  Configuration C;
  hanafuda::LinkerDriver D;
  ScriptConfiguration SC;
  Config = &C;
  Driver = &D;
  ScriptConfig = &SC;

  D.main(Args, CanExitEarly);
  freeArena();
  return !ErrorCount;
}

// This function is called on startup. We need this for LTO since
// LTO calls LLVM functions to compile bitcode files to native code.
// Technically this can be delayed until we read bitcode files, but
// we don't bother to do lazily because the initialization is fast.
static void initLLVM(opt::InputArgList &Args) {
  InitializeAllTargets();
  InitializeAllTargetMCs();
  InitializeAllAsmPrinters();
  InitializeAllAsmParsers();

  // Parse and evaluate -mllvm options.
  std::vector<const char *> V;
  V.push_back("lld (LLVM option parsing)");
  for (auto *Arg : Args.filtered(OPT_mllvm))
    V.push_back(Arg->getValue());
  cl::ParseCommandLineOptions(V.size(), V.data());
}

static const char *getReproduceOption(opt::InputArgList &Args) {
  if (auto *Arg = Args.getLastArg(OPT_reproduce))
    return Arg->getValue();
  return getenv("LLD_REPRODUCE");
}

// Some command line options or some combinations of them are not allowed.
// This function checks for such errors.
static void checkOptions(opt::InputArgList &Args) {
  // The MIPS ABI as of 2016 does not support the GNU-style symbol lookup
  // table which is a relatively new feature.
  if (Config->EMachine == EM_MIPS && Config->GnuHash)
    error("the .gnu.hash section is not compatible with the MIPS target.");

  if (Config->EMachine == EM_AMDGPU && !Config->Entry.empty())
    error("-e option is not valid for AMDGPU.");

  if (Config->Pie && Config->Shared)
    error("-shared and -pie may not be used together");

  if (Config->Relocatable) {
    if (Config->Shared)
      error("-r and -shared may not be used together");
    if (Config->GcSections)
      error("-r and --gc-sections may not be used together");
    if (Config->ICF)
      error("-r and --icf may not be used together");
    if (Config->Pie)
      error("-r and -pie may not be used together");
  }
}

static uint64_t
getZOptionValue(opt::InputArgList &Args, StringRef Key, uint64_t Default) {
  for (auto *Arg : Args.filtered(OPT_z)) {
    StringRef Value = Arg->getValue();
    size_t Pos = Value.find("=");
    if (Pos != StringRef::npos && Key == Value.substr(0, Pos)) {
      Value = Value.substr(Pos + 1);
      uint64_t Result;
      if (Value.getAsInteger(0, Result))
        error("invalid " + Key + ": " + Value);
      return Result;
    }
  }
  return Default;
}

void LinkerDriver::main(ArrayRef<const char *> ArgsArr, bool CanExitEarly) {
  ELFOptTable Parser;
  opt::InputArgList Args = Parser.parse(ArgsArr.slice(1));
  if (Args.hasArg(OPT_help)) {
    Parser.PrintHelp(outs(), ArgsArr[0], "lld-hanafuda", false);
    return;
  }
  if (Args.hasArg(OPT_version))
    outs() << getLLDVersion() << "\n";
  Config->ExitEarly = CanExitEarly && !Args.hasArg(OPT_full_shutdown);

  // Ensure base .dol is provided
  if (!Args.hasArg(OPT_hanafuda_base_dol)) {
    error(Twine("--hanafuda-base-dol=<dol-file> is a required argument of lld-hanafuda"));
    return;
  }
  StringRef dolArg = Args.getLastArgValue(OPT_hanafuda_base_dol);

  // Setup disassembler and code emitter context for performing instruction patching
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();
  llvm::InitializeAllTargetInfos();
  std::string err;
  std::string TT = "powerpc-unknown-hanafuda-eabi";
  std::string CPU = "750cl";
  const llvm::Target *TheTarget = TargetRegistry::lookupTarget(TT, err);
  STI.reset(TheTarget->createMCSubtargetInfo(TT, CPU, ""));
  MRI.reset(TheTarget->createMCRegInfo(TT));
  MAI.reset(TheTarget->createMCAsmInfo(*MRI, TT));
  MCII.reset(TheTarget->createMCInstrInfo());
  Ctx = make_unique<MCContext>(MAI.get(), MRI.get(), nullptr);
  DC.reset(TheTarget->createMCDisassembler(*STI, *Ctx));
  MCE.reset(TheTarget->createMCCodeEmitter(*MCII, *MRI, *Ctx));

  // Read .dol to driver-owned buffer
  Optional<MemoryBufferRef> dolBuffer = readFileCopyBuf(dolArg);
  if (!dolBuffer.hasValue())
    return;
  DolFile.emplace(dolBuffer.getValue(), *this);

  if (DolFile->getUnusedTextSectionIndex() == -1 ||
      DolFile->getUnusedDataSectionIndex() == -1) {
    error("unable to allocate additional section data in " + dolArg);
    return;
  }

  if (const char *Path = getReproduceOption(Args)) {
    // Note that --reproduce is a debug option so you can ignore it
    // if you are trying to understand the whole picture of the code.
    ErrorOr<CpioFile *> F = CpioFile::create(Path);
    if (F) {
      Cpio.reset(*F);
      Cpio->append("response.txt", createResponseFile(Args));
      Cpio->append("version.txt", getLLDVersion() + "\n");
    } else
      error(F.getError(),
            Twine("--reproduce: failed to open ") + Path + ".cpio");
  }

  readConfigs(Args);
  initLLVM(Args);
  createFiles(Args);
  inferMachineType();
  checkOptions(Args);

  if (Config->EKind != ELF32BEKind)
    error("Hanafuda link only accepts ELF32BE kind");
  if (Config->EMachine != EM_PPC)
    error("Hanafuda link only accepts EM_PPC machine");
  if (Config->OSABI != ELF::ELFOSABI_STANDALONE)
    error("Hanafuda link only accepts ELFOSABI_STANDALONE");

  if (ErrorCount)
    return;

  Config->SdaBase = DolFile->getSdataBase();
  Config->Sda2Base = DolFile->getSdata2Base();

  // Do actual link, merging base symbols with linked symbols
  link(Args);
}

// Do actual linking. Note that when this function is called,
// all linker scripts have already been parsed.
void LinkerDriver::link(opt::InputArgList &Args) {
  // Create symbol table and propogate to user code
  SymbolTable<ELF32BE> Symtab;
  elf::Symtab<ELF32BE>::X = &Symtab;

  // Load .dol symbol list if provided and populate Symtab
  if (Args.hasArg(OPT_hanafuda_dol_symbol_list)) {
    StringRef dolListArg = Args.getLastArgValue(OPT_hanafuda_dol_symbol_list);
    Optional<MemoryBufferRef> dolListBuffer = readFile(dolListArg);
    if (dolListBuffer.hasValue()) {
      SymbolListFile DolSymListFile(dolListBuffer.getValue().getBuffer());
      for (const std::pair<uint32_t, StringRef>& sym : DolSymListFile) {
        HanafudaSecType secType;
        int secIdx = 0;
        if (DolFile->validateSymbolAddr(sym.first, secType, secIdx))
          continue;
        DefinedRegular<ELF32BE> *asym = Symtab.addAbsolute(sym.second, llvm::ELF::STV_DEFAULT);
        asym->HanafudaType = secType;
        asym->HanafudaSection = secIdx;
        asym->Value = sym.first;
      }
    }
  }

  // Configure text/data/bss for hanafuda
  ScriptConfig->HasSections = true;
  Config->OFormatBinary = true;
  Config->InitialFileOffset = DolFile->getUnallocatedFileOffset();
  uint32_t InitialAddr = DolFile->getStackEnd();
  Config->Strip = StripPolicy::All;
  Config->OPreWrite = [&,InitialAddr](uint8_t *BufData,
      const std::vector<OutputSectionBase *> &OutputSections) {

    // Patch original calls
    for (const auto &P : Symtab.HanafudaPatches) {
      DefinedRegular<ELF32BE> *OldSym =
          dyn_cast_or_null<DefinedRegular<ELF32BE>>(
                           Symtab.find(P.first()));
      if (!OldSym || OldSym->Section) {
        error("Unable to find original absolute symbol '" +
              P.first() + "' for patching");
        continue;
      }

      DefinedRegular<ELF32BE> *NewSym =
          dyn_cast_or_null<DefinedRegular<ELF32BE>>(
                           Symtab.find(P.second));
      if (!NewSym) {
        error("Unable to find new symbol '" +
              P.second + "' for patching");
        continue;
      }

      if (Config->Verbose)
        outs() << "Patching '" << OldSym->getName() <<
                  "' to '" << NewSym->getName() << "'\n";
      DolFile->patchTargetAddressRelocations(OldSym->Value,
                                             NewSym->getVA<ELF32BE>(0));
    }
    if (ErrorCount)
      return;

    // I'm called after lld has assigned file offsets and VAs to new output sections,
    // and before the file buffer has been committed to disk
    DOLFile::Section *DataSec = nullptr;

    uint64_t Dot = 0;

    // Fill in header information
    for (const OutputSectionBase *Sec : OutputSections) {
      if (!Sec->Offset)
        continue;
      Dot = std::max(Dot, Sec->Addr + Sec->Size);
      if (Sec->getName() == ".sdata") {
        int SDataSecIdx = DolFile->getUnusedDataSectionIndex();
        if (SDataSecIdx == -1) {
          error("Ran out of DOL data sections for .sdata");
          return;
        }
        DOLFile::Section &SDataSec = DolFile->getDataSection(SDataSecIdx);
        SDataSec.Offset = Sec->Offset;
        SDataSec.Addr = Sec->Addr;
        SDataSec.Length = Sec->Size;
      } else if (Sec->getName() == ".sdata2") {
        int SData2SecIdx = DolFile->getUnusedDataSectionIndex();
        if (SData2SecIdx == -1) {
          error("Ran out of DOL data sections for .sdata2");
          return;
        }
        DOLFile::Section &SData2Sec = DolFile->getDataSection(SData2SecIdx);
        SData2Sec.Offset = Sec->Offset;
        SData2Sec.Addr = Sec->Addr;
        SData2Sec.Length = Sec->Size;
      } else if (Sec->getName() == ".htext") {
        int TextSecIdx = DolFile->getUnusedTextSectionIndex();
        if (TextSecIdx == -1) {
          error("Ran out of DOL text sections for .htext");
          return;
        }
        DOLFile::Section &TextSec = DolFile->getTextSection(TextSecIdx);
        TextSec.Offset = Sec->Offset;
        TextSec.Addr = Sec->Addr;
        TextSec.Length = Sec->Size;
      } else {
        if (!DataSec) {
          int DataSecIdx = DolFile->getUnusedDataSectionIndex();
          if (DataSecIdx == -1) {
            error("Ran out of DOL data sections for " + Sec->getName());
            return;
          }
          DataSec = &DolFile->getDataSection(DataSecIdx);
          DataSec->Offset = Sec->Offset;
          DataSec->Addr = Sec->Addr;
        }
        DataSec->Length = (Sec->Addr - DataSec->Addr) + Sec->Size;
      }
    }

    // Relocate __ArenaLo and _stack_base
    if (Dot > InitialAddr) {
      uint32_t Delta = (Dot - InitialAddr + 255) & ~255;
      DolFile->patchForGrowDelta(Delta);
    }

    // Write existing .dol buffer first
    DolFile->writeTo(BufData);

    // When this returns, lld will write out the relocated patch sections
  };

  // Programmatically configure hanafuda linker script
  {
    std::unique_ptr<OutputSectionCommand> SdataOut = make_unique<OutputSectionCommand>(".sdata");
    std::unique_ptr<InputSectionDescription> SdataIn = make_unique<InputSectionDescription>("*");
    SdataIn->SectionPatterns.emplace_back(StringMatcher{}, StringMatcher({".sdata", ".sbss"}));
    SdataIn->SectionPatterns.back().SortOuter = SortSectionPolicy::None;
    SdataIn->SectionPatterns.back().SortInner = SortSectionPolicy::None;
    SdataOut->Commands.push_back(std::move(SdataIn));
    SdataOut->Commands.push_back(make_unique<BytesDataCommand>(0, 4));

    std::unique_ptr<OutputSectionCommand> Sdata2Out = make_unique<OutputSectionCommand>(".sdata2");
    std::unique_ptr<InputSectionDescription> Sdata2In = make_unique<InputSectionDescription>("*");
    Sdata2In->SectionPatterns.emplace_back(StringMatcher{}, StringMatcher({".sdata2", ".sbss2"}));
    Sdata2In->SectionPatterns.back().SortOuter = SortSectionPolicy::None;
    Sdata2In->SectionPatterns.back().SortInner = SortSectionPolicy::None;
    Sdata2Out->Commands.push_back(std::move(Sdata2In));
    Sdata2Out->Commands.push_back(make_unique<BytesDataCommand>(0, 4));

    std::unique_ptr<OutputSectionCommand> TextOut = make_unique<OutputSectionCommand>(".htext");
    std::unique_ptr<InputSectionDescription> TextIn = make_unique<InputSectionDescription>("*");
    TextIn->SectionPatterns.emplace_back(StringMatcher{}, StringMatcher({".text", ".text.*"}));
    TextIn->SectionPatterns.back().SortOuter = SortSectionPolicy::None;
    TextIn->SectionPatterns.back().SortInner = SortSectionPolicy::None;
    TextOut->Commands.push_back(std::move(TextIn));
    TextOut->Commands.push_back(make_unique<BytesDataCommand>(0, 4));

    std::unique_ptr<OutputSectionCommand> DataOut = make_unique<OutputSectionCommand>(".hdata");
    std::unique_ptr<InputSectionDescription> DataIn = make_unique<InputSectionDescription>("*");
    DataIn->SectionPatterns.emplace_back(StringMatcher{}, StringMatcher({".data", ".data.*",
                                                                         ".rodata", ".rodata.*",
                                                                         ".bss"}));
    DataIn->SectionPatterns.back().SortOuter = SortSectionPolicy::None;
    DataIn->SectionPatterns.back().SortInner = SortSectionPolicy::None;
    DataOut->Commands.push_back(std::move(DataIn));
    DataOut->Commands.push_back(make_unique<BytesDataCommand>(0, 4));

    auto Align32Expr = [=](uint64_t Dot) { return (Dot + 31) & ~31; };
    Sdata2Out->AddrExpr = Align32Expr;
    Sdata2Out->AddrExpr = Align32Expr;
    TextOut->AddrExpr = Align32Expr;
    DataOut->AddrExpr = Align32Expr;

    auto InitialStartExpr = [=](uint64_t) { return InitialAddr; };

    ScriptConfig->Commands.push_back(make_unique<SymbolAssignment>(".", InitialStartExpr));
    ScriptConfig->Commands.push_back(std::move(SdataOut));
    ScriptConfig->Commands.push_back(std::move(Sdata2Out));
    ScriptConfig->Commands.push_back(std::move(TextOut));
    ScriptConfig->Commands.push_back(std::move(DataOut));
  }

  // Proceed with standard linker flow
  std::unique_ptr<TargetInfo> TI(createTarget());
  elf::Target = TI.get();
  LinkerScript<ELF32BE> LS;
  ScriptBase = Script<ELF32BE>::X = &LS;

  Config->Rela = false;
  Config->Mips64EL = false;

  // Default output filename is "a.out" by the Unix tradition.
  if (Config->OutputFile.empty())
    Config->OutputFile = "a.out";

  // Handle --trace-symbol.
  for (auto *Arg : Args.filtered(OPT_trace_symbol))
    Symtab.trace(Arg->getValue());

  // Initialize Config->MaxPageSize. The default value is defined by
  // the target, but it can be overriden using the option.
  Config->MaxPageSize =
      getZOptionValue(Args, "max-page-size", elf::Target->MaxPageSize);
  if (!isPowerOf2_64(Config->MaxPageSize))
    error("max-page-size: value isn't a power of 2");

  // Add all files to the symbol table. After this, the symbol table
  // contains all known names except a few linker-synthesized symbols.
  for (InputFile *F : Files)
    Symtab.addFile(F);

  // Add the start symbol.
  // It initializes either Config->Entry or Config->EntryAddr.
  // Note that AMDGPU binaries have no entries.
  if (!Config->Entry.empty()) {
    // It is either "-e <addr>" or "-e <symbol>".
    if (!Config->Entry.getAsInteger(0, Config->EntryAddr))
      Config->Entry = "";
  } else if (!Config->Shared && !Config->Relocatable &&
             Config->EMachine != EM_AMDGPU) {
    // -e was not specified. Use the default start symbol name
    // if it is resolvable.
    Config->Entry = (Config->EMachine == EM_MIPS) ? "__start" : "_start";
  }

  // If an object file defining the entry symbol is in an archive file,
  // extract the file now.
  if (Symtab.find(Config->Entry))
    Symtab.addUndefined(Config->Entry);

  if (ErrorCount)
    return; // There were duplicate symbols or incompatible files

  Symtab.scanUndefinedFlags();
  Symtab.scanShlibUndefined();
  Symtab.scanDynamicList();
  Symtab.scanVersionScript();

  Symtab.addCombinedLTOObject();
  if (ErrorCount)
    return;

  for (auto *Arg : Args.filtered(OPT_wrap))
    Symtab.wrap(Arg->getValue());

  // Now that we have a complete list of input files.
  // Beyond this point, no new files are added.
  // Aggregate all input sections into one place.
  for (elf::ObjectFile<ELF32BE> *F : Symtab.getObjectFiles())
    for (InputSectionBase<ELF32BE> *S : F->getSections())
      if (S && S != &InputSection<ELF32BE>::Discarded)
        Symtab.Sections.push_back(S);
  for (BinaryFile *F : Symtab.getBinaryFiles())
    for (InputSectionData *S : F->getSections())
      Symtab.Sections.push_back(cast<InputSection<ELF32BE>>(S));

  // Do size optimizations: garbage collection and identical code folding.
  if (Config->GcSections)
    markLive<ELF32BE>();
  if (Config->ICF)
    doIcf<ELF32BE>();

  // MergeInputSection::splitIntoPieces needs to be called before
  // any call of MergeInputSection::getOffset. Do that.
  for (InputSectionBase<ELF32BE> *S : Symtab.Sections) {
    if (!S->Live)
      continue;
    if (S->Compressed)
      S->uncompress();
    if (auto *MS = dyn_cast<MergeInputSection<ELF32BE>>(S))
      MS->splitIntoPieces();
  }

  // Write the result to the file.
  writeResult<ELF32BE>();
}

}
}
