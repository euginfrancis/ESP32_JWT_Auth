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

#define CLIENT_EMAIL "pubsub@esp32iot-438916.iam.gserviceaccount.com"   
#include <stdio.h>

const char PRIVATE_KEY[] = "-----BEGIN PRIVATE KEY-----\n"
                            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCtFXIzkl6qMDh7\n"
                            "Kmx0/ldMpvOL1sSUqKIN95+UeTbjQwRE5e/W142psJMttAHdsy1DsCAE4U5Jj/2L\n"
                            "+wWbt4F8eYls9nIlQIdKRrlJnfPsL6AYicfAkj1W/uoz9ZkZgEkbtr4hEoyVAJJF\n"
                            "w7fvnTKkT9Q12IZhX3n2OAricf3pMUprGBSQi2ncgGN1fDFBM9cf90zUVOQlOjdi\n"
                            "rBo9Y584jKNPvuZDFlPfGZuspPsNFmhz+5xjVlbSQiojACAjeaoVt2LC+xc4gjX3\n"
                            "nKJfUfGgjFR60JxqGVK81iKP2IXIAR520nG+5M20RR664ympdvUq4Sd5kk7RR0UQ\n"
                            "LO3MsTrzAgMBAAECggEAQF3dXnhsY/YSyxr3wnpjlMnxgGuaJ36e5XrVCa4aT2G4\n"
                            "0LaB/u+iaxyTX0e1+fCMQMPa5HW1W34E2G29pC8WJGg+RxtPT7MznNe4SDxJXehI\n"
                            "LVfvxRmdXiDmj/Qhv24JwhivlDUFutO/kdo7KQzYrGpTjMK9FrEe9gXZZmTl/DYO\n"
                            "jjQFxcyu0VM5eiO1DzJ/qniOuKB8s3Apxee6713Fwl+zFHeWzGbZ8RY24wWDFcvD\n"
                            "f7cO35Pn+8pRDUbKzsOPpIlrz1Ad/SHUKNCMPhPqePD3JwM+/K0Ht0/w6vtkqz2l\n"
                            "/bvRJyAquey6hKrGyrcBO2GWPYoWjoJIpNzHiP2RoQKBgQDvaX4PtoWmAZ0XOyrr\n"
                            "Fb5u17X2L8FblnPpqs2gruNhArczO2zMfF4fgIAp5kL+Sb3Ew3jfz+MAFPIWF1JW\n"
                            "f06KxBkSEvwb9/iL4tHBHyplh61Kqn5rYt9slusm38zF8I+yhhVWoE7A4UeviP1U\n"
                            "pVC3Kum7Y87otPlE9TX5/XwZ3QKBgQC5E3kfAhRWgoILbPnDrmzj4aa1ixTNCyxY\n"
                            "qZwqaLi974bPyezkqzlgnMfUagdWg+pAVBeHME6Udp5i3u8e6o+5WKp0OY4oBwVC\n"
                            "nIlzZQrYTdvNWpGSYPiPl73FqsprR2PLszWIqjCFeHPURPWNMjiwATKFWHA1EoGa\n"
                            "sGYJeISjDwKBgFoXop6bGtQLi2fwlgf9GLpxZkIMWoDyrw/hfJvY9CvPb81RsXGJ\n"
                            "44mLO6+IvPEgIs9ml5fxjQS83RS/FfcC1TWW8bBBgKmtuNQ7OJ+p8LRgSC/u1L/o\n"
                            "Zxdf+4GXemGKUyjlGCaPENO4ctd1f49Y3nTvKyGfP3+Gir8OX4+Bei/pAoGAQ42B\n"
                            "CzlmFQGD2AnJzIvxAOiPQfpm+ESYxi/6aVxZ+jHggh2RExIQWlw/cB/XV9PEgABx\n"
                            "qg2O0Q/O1gXLP/ybwypC5TNQ2PlfCSY74VvDLpqUnQru0YAFmdvoD6s8QRYIrgRW\n"
                            "iPCdz0nc9WDKQ+RN3qhBOXzDUAvWNJEoXVKZDy8CgYB5i8UFMpEwDRSXD3Kcwf+M\n"
                            "LfOqvCZRiH0jaYmE/AvkkMoPCFoNQewjOLEVP8+ty9V65e1Se3ti8TgY6hWPU+V6\n"
                            "RneAjDVIU39z0rmf603vNmncf69Ky8lVw2neXuY8ApGWmphTT41lcia+THjPKN+g\n"
                            "j6jP+daZg5uhDqjZ0Z2l/w==\n"
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
