# 复制party0的src文件到party1
rm -rf ../party1/App/src/
cp -r ./App/src/ ../party1/App/
echo "party0/App/src/ ==========> party1/App/src"

# 复制party0的Enclave/utils到party1
rm -rf ../party1/Enclave/utils/
cp -r ./Enclave/utils/ ../party1/Enclave/
echo "/party0/Enclave/utils/ ==========> party1/Enclave/utils"

# 复制party0的Enclave.cpp到party1
rm -rf ../party1/Enclave/Enclave.cpp
cp -r ./Enclave/Enclave.cpp ../party1/Enclave/
echo "/party0/Enclave/Enclave.cpp ==========> party1/Enclave/Enclave.cpp"

# 复制party0的Enclave.edl到party1
rm -rf ../party1/Enclave/Enclave.edl
cp -r ./Enclave/Enclave.edl ../party1/Enclave/
echo "/party0/Enclave/Encalve.edl ==========> party1/Enclave/Enclave.edl"
