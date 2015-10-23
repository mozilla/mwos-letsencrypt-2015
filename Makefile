ROOT_DIR := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))

SOURCE := $(ROOT_DIR)/nginx-src
RUN_PATH := $(ROOT_DIR)/run

MYCONFIG := $(ROOT_DIR)/conf/nginx.conf

RUN_CONFIG := $(RUN_PATH)/conf/nginx.conf
RUN_BIN := $(RUN_PATH)/sbin/nginx
PID_FILE := $(RUN_PATH)/logs/nginx.pid

SRC_MKFILE := $(SOURCE)/Makefile
SRC_BIN := $(SOURCE)/objs/nginx

.PHONY: configure build install run \
	clean kill reinstall clean-install \
	run reconfigure

#
# Phony targets
#

default: build

configure: $(SRC_MKFILE)

build: $(SRC_BIN)

install: $(RUN_BIN)

run:
	@test -f "$(RUN_BIN)" || (echo "You have to run 'make install' first"; exit 2)
	"$(RUN_BIN)"

kill:
	test -f "$(PID_FILE)" && kill `cat "$(PID_FILE)"` || echo "Warning: NginX isn't running"

clean-install:
	rm -rf "$(RUN_PATH)"

reinstall: clean-install install

clean-source:
	$(MAKE) -C "$(SOURCE)" clean 2>/dev/null || true

reconfigure: clean-source configure

clean: clean-install clean-source

#
# File targets
#

$(SRC_MKFILE):
	cd "$(SOURCE)"; ./configure --prefix="$(RUN_PATH)" --add-module="$(ROOT_DIR)"

$(SRC_BIN): $(SRC_MKFILE)
#	@test -f $(SRC_MKFILE) || (echo "You have to run 'make configure' first"; exit 2)
	$(MAKE) -C "$(SOURCE)"

$(RUN_BIN): $(SRC_MKFILE)
#	@test -f $(SRC_MKFILE) || (echo "You have to run 'make configure' first"; exit 2)
	$(MAKE) -C "$(SOURCE)" install
	cp "$(MYCONFIG)" "$(RUN_CONFIG)"
