// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This is a very rough prototype of an utility that extracts syscall descriptions from header files.
// It needs to extract struct/union descriptions, better analyze types,
// analyze pointer directions (in, out), figure out len types (usually marked with sal).
// The easiest way to build it is to build it as part of clang. 
// Firstly,add the syz-declextract path to clang-tools-extra:
// then, add the following line to clang-tools-extra's CMakeLists.txt:
// 
// add_subdirectory(syz-declextract)
// 
// It was used to extract windows descriptions:
//   syz-declextract.exe -extra-arg="--driver-mode=cl" Windows.h -- >1.txt

#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"       
#include "clang/Driver/Options.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Rewrite/Core/Rewriter.h"        
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"


using namespace clang;
using namespace clang::tooling;

std::string convertType(ASTContext &C, QualType T) {
  auto name = T.getAsString();
  if (name == "HANDLE")
    return name;
  if (T->isIntegralOrEnumerationType()) {
    int size = C.getTypeSize(T);
    char buf[10];
    sprintf(buf, "int%d", size);
    return buf;
  }
  if (T->isVoidPointerType()) { 
    return "ptr[inout, array[int8]]";
  }
  if (T->isPointerType()) {
    auto inner = convertType(C, T->getPointeeType());
    if (inner == "")
      return "ptr[inout, array[int8]]";
    char buf[1024];
    sprintf(buf, "ptr[inout, %s]", inner.c_str());
    return buf;
  }
  return "intptr";
}

// By implementing RecursiveASTVistor, we can specify which AST nodes
// we're interested in by overriding relevant methods.
class DeclExtractCallVisitor : public RecursiveASTVisitor<DeclExtractCallVisitor> {
 public:

  explicit DeclExtractCallVisitor(ASTContext *Context)
      : Context(*Context) {}


  bool VisitFunctionDecl(const FunctionDecl *D) {
    if (D->doesThisDeclarationHaveABody())
      return true; 
    // TODO(dvyukov): need to select only stdcall (WINAPI) functions.
    // But the following 2 approaches do not work.
    if (false) {
      if (auto *FPT = D->getType()->getAs<FunctionProtoType>()) {
        if (FPT->getExtInfo().getCC() != CC_X86StdCall)
          return true;
      }
    }
    if (false) {
      if (!D->hasAttr<StdCallAttr>())
        return true;
    }
    // Tons of functions are bulk ignored below because they cause
    // static/dynamic link failures, reboot machine, etc.
    auto fn = D->getNameInfo().getAsString();
    //llvm::outs() << "Function name " << fn << "\n";
    if (fn.empty()) return true;
    if (*fn.rbegin() == 'W') return true; // Unicode versions.
    const char *ignore_prefixes[] {
      "_",
      "Rtl",
      "IBind",
      "Ndr",
      "NDR",
      "SCard",
    };
    for (auto prefix: ignore_prefixes) {
      if (strncmp(fn.c_str(), prefix, strlen(prefix)) == 0) return true;
    }
    const char *ignore_functions[] {
      "IEnum",
      "IStream",
      "IType",
      "IService",
      "IProperty",
      "ISequential",
      "IDispatch",
      "I_RPC",
      "I_Rpc",
      "CLEANLOCAL",
      "WinMain",
      "PropertySheet",
      "LookupAccountNameLocalA",
      "LookupAccountSidLocalA",
      "WTSGetServiceSessionId",
      "WTSIsServerContainer",
      "GetDisplayAutoRotationPreferencesByProcessId",
      "LoadStringByReference",
      "IdnToNameprepUnicode",
      "VerFindFileA",
      "VerInstallFileA",
      "GetFileVersionInfoSizeA",
      "GetFileVersionInfoA",
      "GetFileVersionInfoSizeExA",
      "GetFileVersionInfoExA",
      "VerQueryValueA",
      "sndOpenSound",
      "Netbios",
      "RpcBindingGetTrainingContextHandle",
      "RpcAsyncCleanupThread",
      "ShellMessageBoxA",
      "SHEnumerateUnreadMailAccountsA",
      "SHGetUnreadMailCountA",
      "SHSetUnreadMailCountA",
      "GetEncSChannel",
      "CryptExportPKCS8Ex",
      "FindCertsByIssuer",
      "CryptCancelAsyncRetrieval",
      "CryptGetTimeValidObject",
      "CryptFlushTimeValidObject",
      "CryptProtectDataNoUI",
      "CryptUnprotectDataNoUI",
      "NsServerBindSearch",
      "NsClientBindSearch",
      "NsClientBindDone",
      "GetOpenCardNameA",
      "SubscribeServiceChangeNotifications",
      "UnsubscribeServiceChangeNotifications",
      "GetThreadDescription",
      "SetThreadDescription",
      "DialogControlDpi",
      "SetDialogDpiChangeBehavior",
      "GetDialogDpiChangeBehavior",
      "RpcServer",
      "DecodePointer",
      "DecodeRemotePointer",
      "DecodeSystemPointer",
      "EncodePointer",
      "EncodeRemotePointer",
      "EncodeSystemPointer",
      "UnmapViewOfFile2",
      "MapViewOfFileNuma2",
      "DeriveCapabilitySidsFromName",
      "QueryAuxiliaryCounterFrequency",
      "ConvertPerformanceCounterToAuxiliaryCounter",
      "ConvertAuxiliaryCounterToPerformanceCounter",
      "FreePropVariantArray",
      "PropVariantCopy",
      "PropVariantClear",
      "InitiateShutdown",
      "ExitWindowsEx",
      "LockWorkStation",
      "InitiateSystemShutdown",
      "InitiateSystemShutdownEx",
      "shutdown",
      "DebugBreak",
      "DebugBreakProcess",
      "EnableMouseInPointerForThread",
      "CngGetFipsAlgorithmMode",
      "RpcCsGetTags",
      "MIDL_user_allocate",
      "MIDL_user_free",
      "IsApiSetImplemented",
      "LoadEnclaveImageA",
      "CallEnclave",
      "TerminateEnclave",
      "DeleteEnclave",
      "RaiseCustomSystemEventTrigger",
    };
    for (auto func: ignore_functions) {
      if (strstr(fn.c_str(), func)) return true;
    }
    // These are already described:
    const char *ignore_exact[] {
      "CreateFileA",
      "CloseHandle",
      "VirtualAlloc",
      "FindVolumeClose",
      "CreateMemoryResourceNotification",
      "GlobalAlloc",
      "SetFileShortNameA",
      "BackupRead",
      "FindFirstVolumeA",
      "GetEnhMetaFileBits",
      "SetEnhMetaFileBits",
      "SetClipboardData",
      "OpenPrinterA",
      "AddPrinterA",
      "StartPagePrinter",
      "CreateILockBytesOnHGlobal",
      "QueryMemoryResourceNotification",
    };
    for (auto func: ignore_exact) {
      if (strcmp(fn.c_str(), func) == 0) return true;
    }
    const char *ignore_files[] {
      "/um/ole",
      "htiface.h",
      "objbase.h",
      "HLink.h",
      "urlmon.h",
      "HlGuids.h",
      "unknwn.h",
      "unknwnbase.h",
      "coguid.h",
      "MsHtmHst.h",
      "msime.h",
      "ComSvcs.h",
      "combaseapi.h",
      "WbemGlue.h",
      "OCIdl.h",
      "mfapi.h",
      "CompPkgSup.h",
      "ole2.h",
      "Ole2.h",
      "oleidl.h",
      "ObjIdl.h",
      "WabDefs.h",
      "objidl.h",
      "oleauto.h",
    };
    auto src = D->getSourceRange().getBegin().printToString(Context.getSourceManager());
    
    if (strstr(src.c_str(), "ucrt") != NULL)
      return true;
    if (strstr(src.c_str(), "MSVC") != NULL)
      return true;
    //llvm::outs() << "src: " << src << "\n";
    //if (strstr(src.c_str(), "/um/") == 0) return true;
    for (auto file: ignore_files) {
      if (strstr(src.c_str(), file)) return true;
    }
    //llvm::outs() << "after ignore_files\n";
    for (const ParmVarDecl *P : D->parameters()) {
      auto typ = convertType(Context, P->getType());
      if (typ == "") {
        llvm::outs() << D->getNameInfo().getAsString() << ": UNKNOWN TYPE: " <<
            QualType(P->getType()).getAsString() << "\n";
        return true;
      }
    }
    if (Generated[D->getNameInfo().getAsString()])
      return true;
    Generated[D->getNameInfo().getAsString()] = true;

    llvm::outs() << D->getNameInfo().getAsString() << "(";
    int i = 0;
    for (const ParmVarDecl *P : D->parameters()) {
      if (i)
        llvm::outs() << ", ";
      auto name = P->getNameAsString();
      if (name == "") {
        char buf[10];
        sprintf(buf, "arg%d", i);
        name = buf;
      }
      llvm::outs() << name << " " << convertType(Context, P->getType());
      i++;
      if (i == 9)
        break;
    }
    llvm::outs() << ")";
    auto ret = convertType(Context, D->getReturnType());
    if (ret == "HANDLE")
      llvm::outs() << " " << ret;
    llvm::outs() << "\n";
    return true;
  }

 private:
  ASTContext &Context;
  std::map<std::string, bool> Generated;
};

// Implementation of the ASTConsumer interface for reading an AST produced
// by the Clang parser.
class DeclExtractCallConsumer : public clang::ASTConsumer {
 public:
  explicit DeclExtractCallConsumer(ASTContext *Context)
      : Visitor(Context) {}

  virtual void HandleTranslationUnit(clang::ASTContext &Context) {
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
  }

 private:
  DeclExtractCallVisitor Visitor;
};

// For each source file provided to the tool, a new FrontendAction is created.
class DeclExtractCallAction : public clang::ASTFrontendAction {
 public:
  DeclExtractCallAction() {}

  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
      clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
    llvm::outs() << "#** Creating AST consumer for: " << InFile << "\n";
    return std::unique_ptr<clang::ASTConsumer>(
        new DeclExtractCallConsumer(&Compiler.getASTContext()));
  }
};

static llvm::cl::OptionCategory MyToolCategory("my-tool options");

int main(int argc, const char **argv) {
  auto ExpectedParser = CommonOptionsParser::create(argc, argv, MyToolCategory);
  if (!ExpectedParser) {
    // Fail gracefully for unsupported options
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }
  llvm::outs() << "#Start...\n";
  CommonOptionsParser &OptionsParser = ExpectedParser.get();
  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());
  int ret = Tool.run(newFrontendActionFactory<DeclExtractCallAction>().get());
  llvm::outs() << "#ret: " << ret;
  return ret;
}
