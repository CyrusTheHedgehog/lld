//===- tools/hanafuda-lld/hanafuda-lld.cpp - Linker Driver Dispatcher -----===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This is the hanafuda entry point to the lld driver. It always sets up
// an ELF linking flavor for generating .dol patch sections
//
//===----------------------------------------------------------------------===//

#include "lld/Driver/Driver.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"

using namespace lld;
using namespace llvm;
using namespace llvm::sys;

/// Universal linker main(). This linker emulates the gnu, darwin, or
/// windows linker based on the argv[0] or -flavor option.
int main(int Argc, const char **Argv) {
  // Standard set up, so program fails gracefully.
  sys::PrintStackTraceOnErrorSignal(Argv[0]);
  PrettyStackTraceProgram StackPrinter(Argc, Argv);
  llvm_shutdown_obj Shutdown;

  std::vector<const char *> Args(Argv, Argv + Argc);
  return !hanafuda::link(Args);
}
