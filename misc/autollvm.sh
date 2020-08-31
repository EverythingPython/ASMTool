#Check out LLVM:
svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm

#Check out Clang:
cd llvm/tools
svn co http://llvm.org/svn/llvm-project/cfe/trunk clang
cd ../..

#Check out extra Clang tools: (optional)
cd llvm/tools/clang/tools
svn co http://llvm.org/svn/llvm-project/clang-tools-extra/trunk extra
cd ../../../..

#Check out Compiler-RT (optional):
cd llvm/projects
svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt
cd ../..

#Check out libcxx: (only required to build and run Compiler-RT tests on OS X, optional otherwise)
#cd llvm/projects
#svn co http://llvm.org/svn/llvm-project/libcxx/trunk libcxx
#cd ../..

#Build LLVM and Clang:
#mkdir build (in-tree build is not supported)
#cd build
#cmake -G "Unix Makefiles" ../llvm
#make

mkdir llvm-release
cd llvm-release
cmake -G"Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" -DLLVM_USE_LINKER=gold ../llvm
make