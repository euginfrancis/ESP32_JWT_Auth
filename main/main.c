/**
 * main.c
 *
 * Created on: 20.10.2024
 *
 * Copyright (c) 2024 Eugin Francis. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "wifi_manager.h"  
#include "jwt_manager.h"

#define CLIENT_EMAIL "YOUR CLIENT_EMAIL"   
#include <stdio.h>

const char PRIVATE_KEY[] = "-----BEGIN PRIVATE KEY-----\n"
                            "YOUR PRIVATE KEY"
                            "-----END PRIVATE KEY-----\n";

static const char *TAG = "main";
JWTConfig *myConfig;

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_sta();

    ESP_LOGI(TAG,"wifi connect status :%s" ,is_Wifi_Connected() ? "Connected":"Disconnected");

    myConfig = new_JWTConfig();
    myConfig->init_JWT_Auth(myConfig);
    myConfig->client_email = CLIENT_EMAIL;
    myConfig->hashSize = 32;
    myConfig->signatureSize = 256;
    myConfig->private_key = PRIVATE_KEY;

    jwt_encoded_genrate_header(myConfig);
    jwt_encoded_genrate_payload(myConfig);
    jwt_gen_hash(myConfig);
    sign_jwt(myConfig);
    exchangeJwtForAccessToken(myConfig);

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));  
    }
}
