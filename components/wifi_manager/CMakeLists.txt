idf_component_register(SRCS "wifi_manager.c"
                        INCLUDE_DIRS "."
                        REQUIRES esp_wifi nvs_flash freertos)
