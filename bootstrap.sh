#! /bin/bash

echo "Starting release generation for EBF"

echo "Building Passes"
mkdir -p build
cd build
cmake ../pass -DCMAKE_CXX_COMPILER=$LLVM_CXX -DCMAKE_C_COMPILER=$LLVM_CC -DCMAKE_PREFIX_PATH=$LLVM_LIBS
cmake --build .
cd ..

echo "Building Libraries"
cd pass
$LLVM_CC myFunctionslib.c -c -g -o mylibFunctions.o && ar rcs libmylibFunctions.a mylibFunctions.o
$LLVM_CC myDelaylib.c -c -o mylib.o && ar rcs libmylib.a mylib.o
cd ..
mkdir -p lib
cp build/libMemoryTrackPass.so ./lib
cp pass/*.a ./lib
rm pass/*.a
rm pass/*.o
chmod +x ./lib/*
rm -rf build/

echo "Building the Fuzz engine"
mkdir -p fuzzEngine
cd fuzzEngine
if [[ ! -d AFLplusplus ]]
then
    echo "Downloading and compiling AFL++"
    git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git
    cd AFLplusplus
    LLVM_CONFIG=$EBF_LLVM_CONFIG CC=$LLVM_CC CXX=$LLVM_CXX make all -j
    sudo make install
    cd ../
fi
cd ../

chmod +x ./scripts/*
echo "Done"

