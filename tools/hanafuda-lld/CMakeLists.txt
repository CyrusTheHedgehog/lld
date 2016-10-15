add_llvm_executable(hanafuda-lld
  hanafuda-lld.cpp
  )

target_link_libraries(hanafuda-lld
  lldDriver
  lldCOFF
  lldELF
  LLVMSupport
  )

install(TARGETS hanafuda-lld
  RUNTIME DESTINATION bin)

foreach(link ${LLD_SYMLINKS_TO_CREATE})
  add_llvm_tool_symlink(${link} hanafuda-lld ALWAYS_GENERATE)
  # Always generate install targets
  llvm_install_symlink(${link} hanafuda-lld ALWAYS_GENERATE)
endforeach()

