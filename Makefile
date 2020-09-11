
PRJ_DIR := $(shell pwd)
IDF_VER_T := $(shell cd ${IDF_PATH} && git describe --always --tags --dirty)

ifeq ($(EXAMPLE), )
EXAMPLE := helper_project
endif

ifeq ($(SOC), )
SOC := esp32
endif

GEN_LIBS := wpa_supplicant

WIFI_DIR := $(IDF_PATH)/components/esp_wifi/include
WIFI_HFILES := $(WIFI_DIR)/esp_wifi.h \
               $(WIFI_DIR)/esp_wifi_default.h \
               $(WIFI_DIR)/esp_phy_init.h \
               $(WIFI_DIR)/esp_wifi_types.h \
               $(WIFI_DIR)/phy.h \
               $(WIFI_DIR)/esp_wifi_crypto_types.h \
               $(WIFI_DIR)/esp_smartconfig.h \
               $(IDF_PATH)/components/esp_wifi/esp32/include/phy_init_data.h

WIFI_PRIV_DIR := $(WIFI_DIR)/esp_private
WIFI_PRIV_HFILES := $(WIFI_PRIV_DIR)/wifi_os_adapter.h \
                    $(WIFI_PRIV_DIR)/wifi.h \
                    $(WIFI_PRIV_DIR)/esp_wifi_types_private.h \
                    $(WIFI_PRIV_DIR)/esp_wifi_private.h \
                    $(WIFI_PRIV_DIR)/wifi_types.h

COMMON_DIR := $(IDF_PATH)/components/esp_common/include
COMMON_HFILES := $(COMMON_DIR)/esp_err.h \
                 $(COMMON_DIR)/esp_compiler.h \
                 $(COMMON_DIR)/esp_interface.h \
                 $(COMMON_DIR)/esp_timer.h \
                 $(COMMON_DIR)/esp_system.h

EVENT_DIR := $(IDF_PATH)/components/esp_event/include
EVENT_HFILES := $(EVENT_DIR)/esp_event_base.h \
                $(EVENT_DIR)/esp_event.h \
                $(EVENT_DIR)/esp_event_legacy.h

NVS_DIR := $(IDF_PATH)/components/nvs_flash/include
NVS_HFILES := $(NVS_DIR)/nvs.h

WPA_DIR := $(IDF_PATH)/components/wpa_supplicant/include/esp_supplicant
WPA_HFILES := $(WPA_DIR)/esp_wpa.h

LIBS_DIR := $(PRJ_DIR)/libs
INCS_DIR := $(PRJ_DIR)/include

.PHONY: all clean build copy_libs copy_hfiles

all: copy_libs copy_hfiles
	@echo $(IDF_VER_T) > version

clean:
	@cd $(PRJ_DIR)/$(EXAMPLE) && rm build sdkconfig sdkconfig.old -rf
	@rm libs include -rf

build:
	@cd $(IDF_PATH) && . ./export.sh && \
	 cd $(PRJ_DIR)/$(EXAMPLE) && idf.py build

copy_libs: build
	@mkdir -p $(LIBS_DIR)
	@cp $(PRJ_DIR)/$(EXAMPLE)/build/esp-idf/$(GEN_LIBS)/lib$(GEN_LIBS).a $(LIBS_DIR)
	@cp $(IDF_PATH)/components/esp_wifi/lib/$(SOC)/* $(LIBS_DIR)

inc_dirs: build
	@mkdir -p $(INCS_DIR)

config_files: inc_dirs
	@cp $(PRJ_DIR)/$(EXAMPLE)/build/config/sdkconfig.h $(INCS_DIR)
	@cp patch/espidf_types.h $(INCS_DIR)
	@cp patch/espidf_wifi.h $(INCS_DIR)
	@ .
	@cat patch/sdkconfig.h >> $(INCS_DIR)/sdkconfig.h
	@ .
	@sed -i "/CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ/d" $(INCS_DIR)/sdkconfig.h
	@sed -i "/CONFIG_ESP32_TRACEMEM_RESERVE_DRAM/d" $(INCS_DIR)/sdkconfig.h
	@sed -i "/CONFIG_PTHREAD_STACK_MIN/d" $(INCS_DIR)/sdkconfig.h

wifi_files: inc_dirs
	@mkdir -p $(INCS_DIR)/esp_private
	@$(foreach f,$(WIFI_HFILES),cp $(f) $(INCS_DIR) && ) .
	@$(foreach f,$(WIFI_PRIV_HFILES),cp $(f) $(INCS_DIR)/esp_private && ) .
	@ .
	@sed -i "/freertos\/queue.h/d" $(INCS_DIR)/esp_private/wifi.h
	@sed -i "/freertos\/FreeRTOS.h/d" $(INCS_DIR)/esp_private/wifi.h
	@ .
	@sed -i "/freertos\/queue.h/d" $(INCS_DIR)/esp_private/esp_wifi_private.h
	@sed -i "/freertos\/FreeRTOS.h/d" $(INCS_DIR)/esp_private/esp_wifi_private.h

common_files: inc_dirs
	@$(foreach f,$(COMMON_HFILES),cp $(f) $(INCS_DIR) && ) .
	@ .
	@sed -i "/esp_attr.h/d" $(INCS_DIR)/esp_system.h
	@sed -i "/esp_bit_defs.h/d" $(INCS_DIR)/esp_system.h
	@sed -i "/esp_idf_version.h/d" $(INCS_DIR)/esp_system.h

event_files:
	@$(foreach f,$(EVENT_HFILES),cp $(f) $(INCS_DIR) && ) .
	@ .
	@sed -i "/freertos\/FreeRTOS.h/d" $(INCS_DIR)/esp_event.h
	@sed -i "/freertos\/task.h/d" $(INCS_DIR)/esp_event.h
	@sed -i "/freertos\/queue.h/d" $(INCS_DIR)/esp_event.h
	@sed -i "/freertos\/semphr.h/d" $(INCS_DIR)/esp_event.h
	@ .
	@sed -i "/esp_netif.h/d" $(INCS_DIR)/esp_event_legacy.h
	@sed -i "/system_event_ap_staipassigned_t/d" $(INCS_DIR)/esp_event_legacy.h
	@sed -i "/system_event_sta_got_ip_t/d" $(INCS_DIR)/esp_event_legacy.h
	@sed -i "/system_event_got_ip6_t/d" $(INCS_DIR)/esp_event_legacy.h

nvs_files:
	@$(foreach f,$(NVS_HFILES),cp $(f) $(INCS_DIR) && ) .
	@ .
	@sed -i "/esp_attr.h/d" $(INCS_DIR)/nvs.h

wpa_files:
	@$(foreach f,$(WPA_HFILES),cp $(f) $(INCS_DIR) && ) .

copy_hfiles: config_files wifi_files common_files event_files wpa_files nvs_files
