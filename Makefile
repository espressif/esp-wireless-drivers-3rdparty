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

# $(1): File with path
# $(2): Stripped macros list in file
define strip_macros
$(foreach m,$(2),sed -i "/$(m)/d" $(1) &&) .
endef

PRJ_DIR   := $(shell pwd)
IDF_VER_T := $(shell cd ${IDF_PATH} && \
                     git describe --always --tags --dirty && \
                     git log -n 1 | grep "commit")

# Local options

VERISON_FILE := version

INCS_DIR     := $(PRJ_DIR)/include
LIBS_DIR     := $(PRJ_DIR)/libs/$(SOC)
SOC_INCS_DIR := $(PRJ_DIR)/include/$(SOC)

# SoC

SOC_HFS := $(IDF_PATH)/components/esp_wifi/$(SOC)/include/phy_init_data.h

ifeq ($(SOC), esp32)
SDKCONFIG_RMS := CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ \
                 CONFIG_ESP32_TRACEMEM_RESERVE_DRAM \
                 CONFIG_PTHREAD_STACK_MIN
else ifeq ($(SOC), esp32c3)
SDKCONFIG_RMS := CONFIG_ESP32C3_DEFAULT_CPU_FREQ_MHZ \
                 CONFIG_PTHREAD_STACK_MIN
else
$(error soc=$(SOC) is not supported)
endif

# Libs

IDF_COMPONENTS := wpa_supplicant
GEN_LIBS  := $(foreach c,$(IDF_COMPONENTS),$(PRJ_DIR)/$(EXAMPLE)/build/esp-idf/$(c)/lib$(c).a)
WIFI_LIBS := $(IDF_PATH)/components/esp_wifi/lib/$(SOC)/*
ifeq ($(SOC), esp32)
BT_LIBS   := $(IDF_PATH)/components/bt/controller/lib_esp32/esp32/*
else ifeq ($(SOC), esp32c3)
BT_LIBS   := $(IDF_PATH)/components/bt/controller/lib_esp32c3_family/esp32c3/*
else
$(error "No BT libraries")
endif
IDF_LIBS  := $(GEN_LIBS) $(WIFI_LIBS) $(BT_LIBS)

# Types

TYPES_DIR := patch
TYPES_HFS := $(TYPES_DIR)/espidf_types.h \
             $(TYPES_DIR)/espidf_wifi.h

# Wi-Fi

WIFI_DIR     := $(IDF_PATH)/components/esp_wifi/include
WIFI_SRC_HFS := $(WIFI_DIR)/esp_wifi.h \
                $(WIFI_DIR)/esp_wifi_default.h \
                $(WIFI_DIR)/esp_phy_init.h \
                $(WIFI_DIR)/esp_wifi_types.h \
                $(WIFI_DIR)/phy.h \
                $(WIFI_DIR)/esp_wifi_crypto_types.h \
                $(WIFI_DIR)/esp_smartconfig.h \
                $(WIFI_DIR)/esp_coexist_adapter.h \
                $(WIFI_DIR)/esp_coexist_internal.h \
                $(WIFI_DIR)/esp_coexist.h

# Wi-Fi Private

WIFI_PRIV_DIR     := $(WIFI_DIR)/esp_private
WIFI_PRIV_DST_DIR := $(INCS_DIR)/esp_private
WIFI_PRIV_SRC_HFS := $(WIFI_PRIV_DIR)/wifi_os_adapter.h \
                     $(WIFI_PRIV_DIR)/wifi.h \
                     $(WIFI_PRIV_DIR)/esp_wifi_types_private.h \
                     $(WIFI_PRIV_DIR)/esp_wifi_private.h \
                     $(WIFI_PRIV_DIR)/wifi_types.h

WIFI_PRIV_WIFI_DST_HF := $(WIFI_PRIV_DST_DIR)/wifi.h
WIFI_PRIV_WIFI_HF_RMS := freertos\/queue.h \
                         freertos\/FreeRTOS.h

WIFI_PRIV_WIFI_PRIV_DST_HF := $(WIFI_PRIV_DST_DIR)/esp_wifi_private.h
WIFI_PRIV_WIFI_PRIV_HF_RMS := freertos\/queue.h \
                              freertos\/FreeRTOS.h

# Common
COMMON_DIR     := $(IDF_PATH)/components/esp_common/include
COMMON_SRC_HFS := $(COMMON_DIR)/esp_err.h \
                  $(COMMON_DIR)/esp_compiler.h \
                  $(COMMON_DIR)/esp_interface.h

# Event
EVENT_DIR     := $(IDF_PATH)/components/esp_event/include
EVENT_SRC_HFS := $(EVENT_DIR)/esp_event_base.h \
                 $(EVENT_DIR)/esp_event.h \
                 $(EVENT_DIR)/esp_event_legacy.h

EVENT_DST_HF := $(INCS_DIR)/esp_event.h
EVENT_DST_RM := freertos\/FreeRTOS.h \
                freertos\/task.h \
                freertos\/queue.h \
                freertos\/semphr.h

EVENT_LEGACY_DST_HF := $(INCS_DIR)/esp_event_legacy.h
EVENT_LEGACY_HF_RMS := esp_netif.h \
                       system_event_ap_staipassigned_t \
                       system_event_sta_got_ip_t \
                       system_event_got_ip6_t

# NVS
NVS_DIR    := $(IDF_PATH)/components/nvs_flash/include
NVS_SRC_HF := $(NVS_DIR)/nvs.h

NVS_DST_HF := $(INCS_DIR)/nvs.h
NVS_HF_RMS := esp_attr.h

# WPA
WPA_DIR     := $(IDF_PATH)/components/wpa_supplicant/include/esp_supplicant
WPA_SRC_HFS := $(WPA_DIR)/esp_wpa.h \
               $(WPA_DIR)/esp_wpa2.h
# ESP_Timer
ESPTIMER_DIR    := $(IDF_PATH)/components/esp_timer/include
ESPTIMER_SRC_HF := $(ESPTIMER_DIR)/esp_timer.h

# ESP_System
ESPSYSTEM_DIR    := $(IDF_PATH)/components/esp_system/include
ESPSYSTEM_SRC_HF := $(ESPSYSTEM_DIR)/esp_system.h

ESPSYSTEM_DST_HF := $(INCS_DIR)/esp_system.h
ESPSYSTEM_HF_RMS := esp_attr.h \
                    esp_bit_defs.h \
                    esp_idf_version.h

# SDKCONFIG
SDKCONFIG_DST_HF := $(SOC_INCS_DIR)/sdkconfig.h
SDKCONFIG_SRC_HF := $(PRJ_DIR)/$(EXAMPLE)/build/config/sdkconfig.h
SDKCONFIG_PTH_HF := $(PRJ_DIR)/patch/$(SOC)/sdkconfig.h

# BT/BLE
BT_SRC_HF := $(IDF_PATH)/components/bt/include/$(SOC)/include/esp_bt.h
BT_DST_HF := $(SOC_INCS_DIR)/esp_bt.h
BT_HF_RMS := esp_task.h

.PHONY: all clean build copy_libs copy_hfiles

all: copy_libs copy_hfiles
	@echo $(IDF_VER_T) > $(VERISON_FILE)

clean:
	@cd $(PRJ_DIR)/$(EXAMPLE) && rm build sdkconfig sdkconfig.old -rf
	@rm $(LIBS_DIR) $(INCS_DIR) $(SOC_INCS_DIR) -rf

build:
	@cd $(PRJ_DIR)/$(EXAMPLE) && idf.py -DIDF_TARGET=$(SOC) build

copy_libs: build
	@mkdir -p $(LIBS_DIR)
	@$(call copy_files,$(IDF_LIBS),$(LIBS_DIR))

inc_dirs: build
	@mkdir -p $(INCS_DIR)

config_files: inc_dirs
	@$(call copy_files,$(TYPES_HFS),$(INCS_DIR))

wifi_files: inc_dirs
	@mkdir -p $(INCS_DIR)/esp_private
	@$(call copy_files,$(WIFI_SRC_HFS),$(INCS_DIR))
	@$(call copy_files,$(WIFI_PRIV_SRC_HFS),$(WIFI_PRIV_DST_DIR))
	@$(call strip_macros,$(WIFI_PRIV_WIFI_DST_HF),$(WIFI_PRIV_WIFI_HF_RMS))
	@$(call strip_macros,$(WIFI_PRIV_WIFI_PRIV_DST_HF),$(WIFI_PRIV_WIFI_PRIV_HF_RMS))

common_files: inc_dirs
	@$(call copy_files,$(COMMON_SRC_HFS),$(INCS_DIR))

event_files:
	@$(call copy_files,$(EVENT_SRC_HFS),$(INCS_DIR))
	@$(call strip_macros,$(EVENT_DST_HF),$(EVENT_DST_RM))
	@$(call strip_macros,$(EVENT_LEGACY_DST_HF),$(EVENT_LEGACY_HF_RMS))

nvs_files:
	@$(call copy_files,$(NVS_SRC_HF),$(INCS_DIR))
	@$(call strip_macros,$(NVS_DST_HF),$(NVS_HF_RMS))

wpa_files:
	@$(call copy_files,$(WPA_SRC_HFS),$(INCS_DIR))

esptimer_files:
	@$(call copy_files,$(ESPTIMER_SRC_HF),$(INCS_DIR))

espsystem_files:
	@$(call copy_files,$(ESPSYSTEM_SRC_HF),$(INCS_DIR))
	@$(call strip_macros,$(ESPSYSTEM_DST_HF),$(ESPSYSTEM_HF_RMS))

soc_files:
	@mkdir -p $(SOC_INCS_DIR)
	@$(call copy_files,$(SOC_HFS),$(SOC_INCS_DIR))
	@cp $(SDKCONFIG_SRC_HF) $(SOC_INCS_DIR)
	@cat $(SDKCONFIG_PTH_HF) >> $(SDKCONFIG_DST_HF)
	@$(call strip_macros,$(SDKCONFIG_DST_HF),$(SDKCONFIG_RMS))

bt_files:
	@mkdir -p $(SOC_INCS_DIR)
	@$(call copy_files,$(BT_SRC_HF),$(SOC_INCS_DIR))
	@$(call strip_macros,$(BT_DST_HF),$(BT_HF_RMS))

copy_hfiles: config_files wifi_files common_files event_files \
             wpa_files nvs_files esptimer_files espsystem_files \
			 soc_files bt_files
