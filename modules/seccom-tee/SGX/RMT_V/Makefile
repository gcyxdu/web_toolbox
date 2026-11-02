include ./buildenv.mk

all:
	$(MAKE) -f sgx_u.mk LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) all
	$(MAKE) -f sgx_t.mk LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) all

test: all
	$(MAKE) -f sgx_u.mk test

clean:
	$(MAKE) -f sgx_u.mk clean
	$(MAKE) -f sgx_t.mk clean

