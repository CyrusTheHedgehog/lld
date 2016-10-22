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
#include "Strings.h"
#include "SymbolListFile.h"
#include "SymbolTable.h"
#include "Target.h"
#include "Writer.h"
#include "lld/Driver/Driver.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringSwitch.h"
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

using namespace lld;
using namespace lld::elf;

namespace lld {
namespace hanafuda {

class LinkerDriver;

// Maintains structural information about loaded base file
// and template for outputting a new file.
//
// Capable of resolving original data pointers based on
// VAs (runtime addresses) loaded from the symbol list.
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
  Section Texts[7];
  Section Datas[11];
  uint32_t BssAddr;
  uint32_t BssSize;
  uint32_t EntryPoint;

  std::unordered_multimap<uint32_t, uint32_t> OrigCallAddrToInstFileOffs;
  void scanForRelocations(LinkerDriver &Drv);

public:
  DOLFile(MemoryBufferRef M, LinkerDriver &Drv) : MB(M) {
    Header head = *reinterpret_cast<const Header*>(M.getBufferStart());
    head.swapBig();

    for (int i = 0; i < 7; ++i) {
      if (head.TextOffs[i]) {
        Section& sec = Texts[i];
        sec.Offset = head.TextOffs[i];
        sec.Addr = head.TextLoads[i];
        sec.Length = head.TextSizes[i];
      }
    }

    for (int i = 0; i < 11; ++i) {
      if (head.DataOffs[i]) {
        Section& sec = Datas[i];
        sec.Offset = head.DataOffs[i];
        sec.Addr = head.DataLoads[i];
        sec.Length = head.DataSizes[i];
      }
    }

    BssAddr = head.BssAddr;
    BssSize = head.BssSize;
    EntryPoint = head.EntryPoint;

    scanForRelocations(Drv);
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

  StringRef getTextSectionData(int index) const {
    const Section& sec = getTextSection(index);
    return MB.getBuffer().substr(sec.Offset, sec.Length);
  }

  StringRef getDataSectionData(int index) const {
    const Section& sec = getDataSection(index);
    return MB.getBuffer().substr(sec.Offset, sec.Length);
  }

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

  void replaceTargetAddressRelocations(LinkerDriver &Drv,
                                       uint32_t oldAddr, uint32_t newAddr);
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
  void main(ArrayRef<const char *> Args);
};

void DOLFile::scanForRelocations(LinkerDriver &Drv) {
  unsigned ppcLR = Drv.MRI->getRARegister();

  uint64_t Size;
  ArrayRef<uint8_t> Data(reinterpret_cast<const unsigned char*>(
                         MB.getBuffer().data()), MB.getBufferSize());
  for (int s = 0; s < 7; ++s) {
    Section& sec = Texts[s];
    if (!sec.Offset)
      continue;

    for (uint64_t Index = 0; Index < sec.Length; Index += Size) {
      uint64_t FileIndex = sec.Offset + Index;
      uint64_t VAIndex = sec.Addr + Index;

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
        if (Desc.isCall() && Desc.hasImplicitDefOfPhysReg(ppcLR)) {
          for (const MCOperand &op : Inst) {
            if (op.isImm()) {
              OrigCallAddrToInstFileOffs.insert(std::make_pair(op.getImm(), FileIndex));
              break;
            }
          }
        }
        break;
      }
      }
    }
  }
}

void DOLFile::replaceTargetAddressRelocations(LinkerDriver &Drv,
                                              uint32_t oldAddr, uint32_t newAddr) {
  auto range = OrigCallAddrToInstFileOffs.equal_range(oldAddr);
  for (auto it = range.first; it != range.second; ++it) {
    it->second;
  }
}

bool link(ArrayRef<const char *> Args, raw_ostream &Error) {
  HasError = false;
  ErrorOS = &Error;

  Configuration C;
  LinkerDriver D;
  ScriptConfiguration SC;
  Config = &C;
  Driver = &D;
  ScriptConfig = &SC;

  static_cast<LinkerDriver*>(Driver)->main(Args);
  InputFile::freePool();
  return !HasError;
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

  // This is a flag to discard all but GlobalValue names.
  // We want to enable it by default because it saves memory.
  // Disable it only when a developer option (-save-temps) is given.
  Driver->Context.setDiscardValueNames(!Config->SaveTemps);
  Driver->Context.enableDebugTypeODRUniquing();

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

void LinkerDriver::main(ArrayRef<const char *> ArgsArr) {
  ELFOptTable Parser;
  opt::InputArgList Args = Parser.parse(ArgsArr.slice(1));
  if (Args.hasArg(OPT_help)) {
    Parser.PrintHelp(outs(), ArgsArr[0], "lld-hanafuda", false);
    return;
  }
  if (Args.hasArg(OPT_version))
    outs() << getVersionString();

  // Ensure base .dol is provided
  if (!Args.hasArg(OPT_hanafuda_base_dol)) {
    error(Twine("--hanafuda-base-dol=<dol-file> is a required argument of lld-hanafuda"));
    return;
  }
  StringRef dolArg = Args.getLastArgValue(OPT_hanafuda_base_dol);

  // Read .dol to driver-owned buffer
  Optional<MemoryBufferRef> dolBuffer = readFile(dolArg);
  if (!dolBuffer.hasValue()) return;
  DolFile.emplace(dolBuffer.getValue(), *this);

  if (const char *Path = getReproduceOption(Args)) {
    // Note that --reproduce is a debug option so you can ignore it
    // if you are trying to understand the whole picture of the code.
    ErrorOr<CpioFile *> F = CpioFile::create(Path);
    if (F) {
      Cpio.reset(*F);
      Cpio->append("response.txt", createResponseFile(Args));
      Cpio->append("version.txt", getVersionString());
    } else
      error(F.getError(),
            Twine("--reproduce: failed to open ") + Path + ".cpio");
  }

  readConfigs(Args);
  initLLVM(Args);
  createFiles(Args);
  checkOptions(Args);
  if (HasError)
    return;

  // Setup disassembler and code emitter context for performing instruction patching
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

  // Do actual link, merging base symbols with linked symbols
  link(Args);
}

// Override symbol replace trigger to ensure .dol-sourced symbols are patched
class HanafudaSymbolTable : public SymbolTable<ELF32BE> {
  LinkerDriver &D;
  bool replaceDefinedSymbolPreTrigger(Symbol *S, StringRef Name) override {
    SymbolBody *body = S->body();
    if (body->isUndefined())
      return false;
    if (const auto *DR = dyn_cast<DefinedRegular<ELF32BE>>(body)) {
      D.DolFile->replaceTargetAddressRelocations(D, DR->Value, 0);
    }
    return false;
  }
public:
  HanafudaSymbolTable(LinkerDriver &Din) : D(Din) {}
};

// Do actual linking. Note that when this function is called,
// all linker scripts have already been parsed.
void LinkerDriver::link(opt::InputArgList &Args) {
  // Create symbol table and propogate to user code
  HanafudaSymbolTable Symtab(*this);
  elf::Symtab<ELF32BE>::X = &Symtab;

  // Load symbol list if provided and populate Symtab
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

  std::unique_ptr<TargetInfo> TI(createTarget());
  TargetInfo *Target = TI.get();
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

  // Initialize Config->ImageBase.
  if (auto *Arg = Args.getLastArg(OPT_image_base)) {
    StringRef S = Arg->getValue();
    if (S.getAsInteger(0, Config->ImageBase))
      error(Arg->getSpelling() + ": number expected, but got " + S);
    else if ((Config->ImageBase % Target->MaxPageSize) != 0)
      warn(Arg->getSpelling() + ": address isn't multiple of page size");
  } else {
    Config->ImageBase = Config->Pic ? 0 : Target->DefaultImageBase;
  }

  // Initialize Config->MaxPageSize. The default value is defined by
  // the target, but it can be overriden using the option.
  Config->MaxPageSize =
      getZOptionValue(Args, "max-page-size", Target->MaxPageSize);
  if (!isPowerOf2_64(Config->MaxPageSize))
    error("max-page-size: value isn't a power of 2");

  // Add all files to the symbol table. After this, the symbol table
  // contains all known names except a few linker-synthesized symbols.
  for (InputFile *F : Files)
    Symtab.addFile(F);

  // Add the start symbol.
  // It initializes either Config->Entry or Config->EntryAddr.
  // Note that AMDGPU binaries have no entries.
  bool HasEntryAddr = false;
  if (!Config->Entry.empty()) {
    // It is either "-e <addr>" or "-e <symbol>".
    HasEntryAddr = !Config->Entry.getAsInteger(0, Config->EntryAddr);
  } else if (!Config->Shared && !Config->Relocatable &&
             Config->EMachine != EM_AMDGPU) {
    // -e was not specified. Use the default start symbol name
    // if it is resolvable.
    Config->Entry = (Config->EMachine == EM_MIPS) ? "__start" : "_start";
  }
  if (!HasEntryAddr && !Config->Entry.empty()) {
    if (Symtab.find(Config->Entry))
      Config->EntrySym = Symtab.addUndefined(Config->Entry);
    else
      warn("entry symbol " + Config->Entry + " not found, assuming 0");
  }

  if (HasError)
    return; // There were duplicate symbols or incompatible files

  Symtab.scanUndefinedFlags();
  Symtab.scanShlibUndefined();
  Symtab.scanDynamicList();
  Symtab.scanVersionScript();

  Symtab.addCombinedLtoObject();
  if (HasError)
    return;

  for (auto *Arg : Args.filtered(OPT_wrap))
    Symtab.wrap(Arg->getValue());

  // Do size optimizations: garbage collection and identical code folding.
  if (Config->GcSections)
    markLive<ELF32BE>();
  if (Config->ICF)
    doIcf<ELF32BE>();

  // MergeInputSection::splitIntoPieces needs to be called before
  // any call of MergeInputSection::getOffset. Do that.
  for (elf::ObjectFile<ELF32BE> *F : Symtab.getObjectFiles()) {
    for (InputSectionBase<ELF32BE> *S : F->getSections()) {
      if (!S || S == &InputSection<ELF32BE>::Discarded || !S->Live)
        continue;
      if (S->Compressed)
        S->uncompress();
      if (auto *MS = dyn_cast<MergeInputSection<ELF32BE>>(S))
        MS->splitIntoPieces();
    }
  }

  // Write the result to the file.
  writeResult<ELF32BE>();
}

}
}
