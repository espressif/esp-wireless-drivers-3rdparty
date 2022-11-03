ifeq ($(EXAMPLE), )
EXAMPLE := helper_project
endif

ifeq ($(SOC), )
SOC := esp32
endif

# $(1): Files list with path
# $(2): Target directory
define copy_files
$(foreach f,$(1),cp $(f) $(2) && ) .
endef

PRJ_DIR   := $(shell pwd)
IDF_VER_T := $(shell cd ${IDF_PATH} && \
                     git describe --always --tags --dirty && \
                     git log -n 1 | grep "commit")

# Local options

VERISON_FILE := version

LIBS_DIR     := $(PRJ_DIR)/libs/$(SOC)

# Libs

IDF_COMPONENTS := wpa_supplicant
WIFI_LIBS := $(IDF_PATH)/components/esp_wifi/lib/$(SOC)/*
ifeq ($(SOC), esp32)
BT_LIBS   := $(IDF_PATH)/components/bt/controller/lib_esp32/esp32/*
else ifeq ($(SOC), esp32c3)
BT_LIBS   := $(IDF_PATH)/components/bt/controller/lib_esp32c3_family/esp32c3/*
else
$(error "No BT libraries")
endif
IDF_LIBS  := $(GEN_LIBS) $(WIFI_LIBS) $(BT_LIBS)

.PHONY: all clean distclean build copy_libs

all: copy_libs
	@echo $(IDF_VER_T) > $(VERISON_FILE)

clean:
	@cd $(PRJ_DIR)/$(EXAMPLE) && rm -rf build sdkconfig sdkconfig.old

distclean: clean
	@rm -rf $(LIBS_DIR)

build:
	@cd $(PRJ_DIR)/$(EXAMPLE) && idf.py -DIDF_TARGET=$(SOC) build

copy_libs: build
	@mkdir -p $(LIBS_DIR)
	@$(call copy_files,$(IDF_LIBS),$(LIBS_DIR))
