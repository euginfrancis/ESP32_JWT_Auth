idf_component_register(SRCS "jwt_manager.c"
                        INCLUDE_DIRS "."
                        REQUIRES esp_http_client cJSON mbedtls freertos nvs_flash)
