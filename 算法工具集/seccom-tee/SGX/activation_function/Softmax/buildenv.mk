ROOT_DIR := /home/user/intel-sgx-ssl/intel-sgx-ssl/Linux/sgx
export PACKAGE_LIB := $(ROOT_DIR)/../package/lib64/
export PACKAGE_INC := $(ROOT_DIR)/../package/include/
export TRUSTED_LIB_DIR := $(ROOT_DIR)/libsgx_tsgxssl/
export UNTRUSTED_LIB_DIR := $(ROOT_DIR)/libsgx_usgxssl/
export OS_ID=0
export LINUX_SGX_BUILD ?= 0
export TRUSTED_LIB := libsgx_tsgxssl.a
export UNTRUSTED_LIB := libsgx_usgxssl.a
export SGX_SDK ?= /opt/intel/sgxsdk/
export VCC := @$(CC)
export VCXX := @$(CXX)
export OBJDIR := release
DESTDIR ?= /opt/intel/sgxssl/
DEBUG ?= 1		#试试调试，把这个改成1
$(shell mkdir -p $(PACKAGE_LIB))
UBUNTU_CONFNAME:=/usr/include/x86_64-linux-gnu/bits/confname.h
ifneq ("$(wildcard $(UBUNTU_CONFNAME))","")
	OS_ID=1
else ifeq ($(origin NIX_STORE),environment)
	OS_ID=3
else
	OS_ID=2
endif
ifeq ($(DEBUG), 1)
	OBJDIR := debug
	OPENSSL_LIB := libsgx_tsgxssl_cryptod.a
	TRUSTED_LIB := libsgx_tsgxssld.a
	UNTRUSTED_LIB := libsgx_usgxssld.a
else			#pay attention
	OBJDIR := release
	OPENSSL_LIB := libsgx_tsgxssl_crypto.a
	TRUSTED_LIB := libsgx_tsgxssl.a
	UNTRUSTED_LIB := libsgx_usgxssl.a
endif

ifeq ($(VERBOSE),1)
      VCC=$(CC)
      VCXX=$(CXX)
else
      VCC=@$(CC)
      VCXX=@$(CXX)
endif
