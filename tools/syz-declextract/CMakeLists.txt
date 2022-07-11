set(LLVM_LINK_COMPONENTS
  Support
  )

add_clang_executable(syz-declextract 
  syz-declextract.cpp
  )

target_link_libraries(syz-declextract
  PRIVATE
  clangAST
  clangDriver
  clangFrontend
  clangRewrite
  clangTooling
  )