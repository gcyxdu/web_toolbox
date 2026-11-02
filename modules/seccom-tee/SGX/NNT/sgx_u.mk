######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64
UNTRUSTED_DIR=App

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	ifeq ($(LINUX_SGX_BUILD), 1)		
		include ../../../../../buildenv.mk
		SGX_LIBRARY_PATH := $(BUILD_DIR)
		SGX_EDGER8R := $(BUILD_DIR)/sgx_edger8r
		SGX_SDK_INC := $(COMMON_DIR)/inc
		SGX_SHARED_LIB_FLAG := -Wl,-rpath,${SGX_LIBRARY_PATH}
	else
		SGX_LIBRARY_PATH := $(SGX_SDK)/lib64		
		SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
	endif
endif

ifeq ($(DEBUG), 1)	# DEBUG默认是0
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

OPENSSL_LIBRARY_PATH := $(PACKAGE_LIB)
ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g 
		SgxSSL_Link_Libraries := sgx_usgxssld
else
        # SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
		SgxSSL_Link_Libraries := sgx_usgxssl
endif

######## App Settings ########
App_Cpp_Files := $(UNTRUSTED_DIR)/TestApp.cpp $(UNTRUSTED_DIR)/layer.cpp $(UNTRUSTED_DIR)/network.cpp $(UNTRUSTED_DIR)/she.cpp $(UNTRUSTED_DIR)/sheFloat.cpp
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Include_Paths := -I$(UNTRUSTED_DIR) -I$(SGX_SDK_INC)

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -fpie -Wformat -Wformat-security -Wno-attributes $(App_Include_Paths) 
App_Cpp_Flags := $(App_C_Flags) -std=c++11

#默认HW=0
ifneq ($(SGX_MODE), HW)					
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts		
	UaeService_Library_Name := sgx_uae_service
endif

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

#App_Link_Flags := $(SGX_COMMON_CFLAGS) $(Security_Link_Flags) $(SGX_SHARED_LIB_FLAG) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name) -L$(OPENSSL_LIBRARY_PATH) -l$(SgxSSL_Link_Libraries) -lpthread 
App_Link_Flags := $(SGX_COMMON_CFLAGS) $(SGX_SHARED_LIB_FLAG) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name) -L$(OPENSSL_LIBRARY_PATH) -l$(SgxSSL_Link_Libraries) -lpthread


.PHONY: all test

all: app

test: all
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## App Objects ########
$(UNTRUSTED_DIR)/TestEnclave_u.c: $(SGX_EDGER8R) enclave/TestEnclave.edl
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --untrusted ../enclave/TestEnclave.edl --search-path $(PACKAGE_INC) --search-path $(SGX_SDK_INC)
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/TestEnclave_u.o: $(UNTRUSTED_DIR)/TestEnclave_u.c
	$(VCC) $(App_C_Flags) -fPIC -c $< -o $@ -g 
	@echo "CC   <=  $<"

$(UNTRUSTED_DIR)/%.o: $(UNTRUSTED_DIR)/%.cpp $(UNTRUSTED_DIR)/TestEnclave_u.c
	$(VCXX) $(App_Cpp_Flags) -fPIC -c $< -o $@ -g 
	@echo "CXX  <=  $<"

app: $(UNTRUSTED_DIR)/TestEnclave_u.o $(App_Cpp_Objects)
	$(VCXX)  $^ -o $@ $(App_Link_Flags) -lcrypto -g -pg
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f app  $(App_Cpp_Objects) $(UNTRUSTED_DIR)/TestEnclave_u.* ./test.so
