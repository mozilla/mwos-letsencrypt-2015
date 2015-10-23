ROOT_DIR := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))

SRC_VERSION := nginx-1.9.5
SRC_LINK := "http://nginx.org/download/$(SRC_VERSION).tar.gz"

SRC_PATH := $(ROOT_DIR)/$(SRC_VERSION)
RUN_PATH := $(ROOT_DIR)/run

MYCONFIG := $(ROOT_DIR)/conf/nginx.conf

RUN_CONFIG := $(RUN_PATH)/conf/nginx.conf
RUN_BIN := $(RUN_PATH)/sbin/nginx
PID_FILE := $(RUN_PATH)/logs/nginx.pid

SRC_MKFILE := $(SRC_PATH)/Makefile
SRC_BIN := $(SRC_PATH)/objs/nginx

.PHONY: default source configure build install run \
	clean kill reinstall clean-install clean-all \
	run reconfigure clean-build clean-source

#
# Phony targets
#

default: build

all: source install

source: clean-source
	mkdir -p "$(SRC_PATH)"
	curl $(SRC_LINK) | tar xz

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

clean-build:
	$(MAKE) -C "$(SRC_PATH)" clean 2>/dev/null || true

reconfigure: clean-build configure

clean: clean-install clean-build

clean-source:
	rm -rf $(SRC_PATH)

clean-all: clean clean-source

#
# File targets
#

$(SRC_MKFILE):
	@test -d $(SRC_PATH) || (echo "You have to run 'make source' first to download the Nginx source code"; exit 2)
	cd "$(SRC_PATH)"; ./configure --prefix="$(RUN_PATH)" --add-module="$(ROOT_DIR)"

$(SRC_BIN): $(SRC_MKFILE)
	$(MAKE) -C "$(SRC_PATH)"

$(RUN_BIN): $(SRC_MKFILE)
	$(MAKE) -C "$(SRC_PATH)" install
	cp "$(MYCONFIG)" "$(RUN_CONFIG)"
