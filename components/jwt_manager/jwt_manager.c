/**
 * jwt_manager.c
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
#include <string.h>
#include "esp_sntp.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "cJSON.h"
#include "jwt_manager.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pem.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_system.h" 
#include "esp_mac.h"
#include "esp_err.h"

static const char *TAG = "JWTManager";
const char *cacert = "-----BEGIN CERTIFICATE-----\n"
                    "MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw\n"
                    "CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU\n"
                    "MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw\n"
                    "MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp\n"
                    "Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA\n"
                    "A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo\n"
                    "27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w\n"
                    "Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw\n"
                    "TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl\n"
                    "qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH\n"
                    "szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8\n"
                    "Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk\n"
                    "MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92\n"
                    "wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p\n"
                    "aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN\n"
                    "VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID\n"
                    "AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E\n"
                    "FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb\n"
                    "C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe\n"
                    "QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy\n"
                    "h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4\n"
                    "7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J\n"
                    "ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef\n"
                    "MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/\n"
                    "Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT\n"
                    "6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ\n"
                    "0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm\n"
                    "2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb\n"
                    "bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c\n"
                    "-----END CERTIFICATE-----\n";


static bool encodeUrl(char *encoded, unsigned char *string, size_t len)
{
    size_t i;
    char *p = encoded;
    if(!encoded || !string) return false;
    
    for (i = 0; i < len -2; i += 3)
    {
        *p++ = base64EncBuff[(string[i] >> 2) & 0x3F];
        *p++ = base64EncBuff[((string[i] & 0x3) << 4) | ((int)(string[i + 1] & 0xF0) >> 4)];
        *p++ = base64EncBuff[((string[i + 1] & 0xF) << 2) | ((int)(string[i + 2] & 0xC0) >> 6)];
        *p++ = base64EncBuff[string[i + 2] & 0x3F];
    }

    if (i < len)
    {
        *p++ = base64EncBuff[(string[i] >> 2) & 0x3F];
        if (i == (len - 1))
            *p++ = base64EncBuff[((string[i] & 0x3) << 4)];
        else
        {
            *p++ = base64EncBuff[((string[i] & 0x3) << 4) | ((int)(string[i + 1] & 0xF0) >> 4)];
            *p++ = base64EncBuff[((string[i + 1] & 0xF) << 2)];
        }
    }
    *p++ = '\0';
    return true;
}

static bool concatStrings(char **str1, char *str2) {
    
    if (str2 == NULL) {
        ESP_LOGI(TAG, "concatStrings: str2 is null");
        return false;
    }

    size_t len1 = (*str1 != NULL) ? strlen(*str1) : 0;
    size_t len2 = strlen(str2);
    size_t totalLength = len1 + len2 + 1; 

    char *combined = (char *)realloc(*str1,totalLength);  
    
    if (combined == NULL) {
        ESP_LOGI(TAG, "concatStrings: failed to allocate memory");
        return false;
    }

    *str1 = combined;  
    strcpy(combined + len1, str2);  
    return true;
}

JWTConfig *new_JWTConfig() {
    JWTConfig *myConfig = calloc(1,sizeof(JWTConfig));
    myConfig->init_JWT_Auth = init_JWT_Auth;
    return myConfig;
}
void init_JWT_Auth(JWTConfig *myConfig){
    if(myConfig){
        myConfig->token_error = false;
        myConfig->token_ready = false;
        myConfig->step = step_jwt_encoded_genrate_header;
        myConfig->time_sync_finished = false;
    }
}
static time_t getTime() {
    ESP_LOGI(TAG, "Configuring time...");

    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_setservername(1, "time.nist.gov");
    esp_sntp_init();

    while (sntp_get_sync_status() != SNTP_SYNC_STATUS_COMPLETED) {
        ESP_LOGI(TAG, "Waiting For Time");
        vTaskDelay(pdMS_TO_TICKS(1000)); 
    }

    struct tm timeinfo;
    time_t now = time(NULL); 
    localtime_r(&now, &timeinfo); 

    ESP_LOGI(TAG, "Current time: %s", asctime(&timeinfo));

    return now; 
}

static char* base64_encode(unsigned char *input, size_t length) {
    if(!input || length <1) return NULL;

    char *output = CREATE_CHAR_BUFFER(MBEDTLS_BASE64_ENCODE_OUTPUT(length));
    if (!output) {
        ESP_LOGE(TAG, "Failed to allocate memory for Base64 output");
        return NULL;
    }
    encodeUrl(output,input,length);
    return output;
}

void jwt_encoded_genrate_header(JWTConfig *myConfig){

    cJSON *jsonPtr = cJSON_CreateObject();
    if (!jsonPtr) {
        ESP_LOGE(TAG, "Failed to create JSON object");
        return;
    }

    cJSON_AddItemToObject(jsonPtr, esp_signer_gauth_pgm_str_20, cJSON_CreateString("RS256")); 
    cJSON_AddItemToObject(jsonPtr, esp_signer_gauth_pgm_str_22, cJSON_CreateString("JWT"));   

    myConfig->jwt_components.header = cJSON_PrintUnformatted(jsonPtr);
    if (!myConfig->jwt_components.header) {
        ESP_LOGE(TAG, "Failed to print JSON");
        cJSON_Delete(jsonPtr);
        return;
    }

    myConfig->jwt_components.encHeader = base64_encode((unsigned char *)myConfig->jwt_components.header, strlen(myConfig->jwt_components.header));
    if (!myConfig->jwt_components.encHeader) {
        ESP_LOGE(TAG, "Failed to encode JSON to Base64");
        free(myConfig->jwt_components.header);
        cJSON_Delete(jsonPtr);
        return;
    }
    myConfig->jwt_components.encHeadPayload = myConfig->jwt_components.encHeader;
   // ESP_LOGI(TAG, "Encoded Header: %s , %s", myConfig->encHeadPayload,myConfig->header);
    free(myConfig->jwt_components.header);
    cJSON_Delete(jsonPtr);
    myConfig->step = step_jwt_encoded_genrate_payload;
}

void jwt_encoded_genrate_payload(JWTConfig *myConfig){
    time_t now;

    if(!myConfig->time_sync_finished){
        now =  getTime(); 
        myConfig->time_sync_finished = true;
    }else{
        now = time(NULL);
    }
    cJSON *jsonPtr = cJSON_CreateObject();

    if (!jsonPtr) {
        ESP_LOGE(TAG, "Failed to create JSON object");
        return;
    }

    cJSON_AddStringToObject(jsonPtr, esp_signer_gauth_pgm_str_24, myConfig->client_email);
    cJSON_AddStringToObject(jsonPtr, esp_signer_gauth_pgm_str_25, myConfig->client_email);

    cJSON_AddStringToObject(jsonPtr, esp_signer_gauth_pgm_str_47, googleapis_auth2_url);
    cJSON_AddNumberToObject(jsonPtr, esp_signer_gauth_pgm_str_31, (int)now);
    cJSON_AddNumberToObject(jsonPtr, esp_signer_gauth_pgm_str_32, (int)(now + 3600));
    cJSON_AddStringToObject(jsonPtr, esp_signer_gauth_pgm_str_33, googleapis_scope_url);

    myConfig->jwt_components.payload = cJSON_PrintUnformatted(jsonPtr); 
    if(myConfig->jwt_components.payload == NULL){
        ESP_LOGE(TAG, "Failed to encode JSON to Base64");
        cJSON_Delete(jsonPtr); 
        return;
    }

    myConfig->jwt_components.encPayload = base64_encode((unsigned char *)myConfig->jwt_components.payload, strlen(myConfig->jwt_components.payload));
    if(myConfig->jwt_components.encPayload == NULL){
        ESP_LOGE(TAG, "Failed to encode JSON to Base64");
        free(myConfig->jwt_components.payload);
        cJSON_Delete(jsonPtr);
        return;
    }

    concatStrings(&myConfig->jwt_components.encHeadPayload,esp_signer_gauth_pgm_str_35);
    concatStrings(&myConfig->jwt_components.encHeadPayload,myConfig->jwt_components.encPayload);

    //ESP_LOGI(TAG, "Encoded Payload: %s , %s", myConfig->payload,myConfig->encHeadPayload);

    free(myConfig->jwt_components.payload); 
    free(myConfig->jwt_components.encPayload);  
    cJSON_Delete(jsonPtr); 
    myConfig->step = step_jwt_gen_hash;
}

int mbedtls_error_log(int error){
    if(error < 0){
        char *error_buf = CREATE_CHAR_BUFFER(ERROR_BUFFER_SIZE);
        if(error_buf == NULL){
            ESP_LOGE(TAG,"Failed allocate memmory for error buff");
            return error;
        }
        mbedtls_strerror(-error, error_buf, ERROR_BUFFER_SIZE);
        ESP_LOGE(TAG,"Error: %s\n", error_buf); 
        free(error_buf);
    }
    return error;
}

void jwt_gen_hash(JWTConfig *myConfig){
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);

    if(mbedtls_error_log(mbedtls_sha256_starts(&sha_ctx, 0))<0){
        mbedtls_sha256_free(&sha_ctx);
        return;
    }

    if(mbedtls_error_log(mbedtls_sha256_update(&sha_ctx, 
                        (unsigned char *)myConfig->jwt_components.encHeadPayload, strlen(myConfig->jwt_components.encHeadPayload)))<0){
        mbedtls_sha256_free(&sha_ctx);
        return; 
    }
    
    myConfig->jwt_components.hash = CREATE_CHAR_BUFFER(myConfig->hashSize);
    if (myConfig->jwt_components.hash == NULL) {
        return;
    }

    if(mbedtls_error_log(mbedtls_sha256_finish(&sha_ctx, (unsigned char *)myConfig->jwt_components.hash))<0){
        mbedtls_sha256_free(&sha_ctx);
        return;
    }

    mbedtls_sha256_free(&sha_ctx);
    myConfig->step = step_sign_jwt;
}
int my_rng(void *ctx, unsigned char *output, size_t len) {
    return mbedtls_ctr_drbg_random((mbedtls_ctr_drbg_context *)ctx, output, len);
}

void sign_jwt(JWTConfig *myConfig){  
    concatStrings(&myConfig->jwt_components.jwt,myConfig->jwt_components.encHeadPayload);
    free(myConfig->jwt_components.encHeadPayload);
    concatStrings(&myConfig->jwt_components.jwt,esp_signer_gauth_pgm_str_35);
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if(mbedtls_error_log(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func , &entropy, NULL, 0))<0)return;

    if(mbedtls_error_log(mbedtls_pk_parse_key(&pk, (const unsigned char *)myConfig->private_key, 
                                strlen(myConfig->private_key) + 1, NULL, 0, mbedtls_ctr_drbg_random,
                                &ctr_drbg))<0){
        mbedtls_pk_free(&pk);
        return;
    }
    ESP_LOGI(TAG, "Signing started");

    size_t sig_len;

    myConfig->jwt_components.signature = CREATE_CHAR_BUFFER(MBEDTLS_MPI_MAX_SIZE);
    if (myConfig->jwt_components.signature == NULL) {
        ESP_LOGE(TAG,"Can allocate memmory for signature"); 
        return;    
    }

    if(mbedtls_error_log(mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, (const unsigned char *)myConfig->jwt_components.hash,
                               myConfig->hashSize,  (unsigned char *)myConfig->jwt_components.signature,
                               myConfig->signatureSize,&sig_len, mbedtls_ctr_drbg_random, &ctr_drbg))<0){
        free(myConfig->jwt_components.signature);  
        mbedtls_pk_free(&pk);       
        return;
    }
    
    mbedtls_pk_free(&pk);
    myConfig->jwt_components.encSignature = base64_encode((unsigned char *)myConfig->jwt_components.signature,myConfig->signatureSize);
    free(myConfig->jwt_components.signature);
    concatStrings(&myConfig->jwt_components.jwt,myConfig->jwt_components.encSignature);
    free(myConfig->jwt_components.encSignature);
    myConfig->step = step_exchangeJwtForAccessToken;
}


static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    JWTConfig *myConfig = (JWTConfig *)evt->user_data;
    static int total_len = 0;
    static char *response_data = NULL;
    
    switch (evt->event_id) {
       case HTTP_EVENT_ERROR:
            ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            if (!esp_http_client_is_chunked_response(evt->client)) {
                char *response = (char *)malloc(evt->data_len + 1);
                if(response == NULL){
                    ESP_LOGE(TAG, "Failed to allocate memory for response");
                    free(response);
                    return ESP_FAIL; 
                }
                memcpy(response, evt->data, evt->data_len);
                response[evt->data_len] = 0;
                ESP_LOGI(TAG, "HTTP Response: %s", response);
                free(response);
            }else{
                if (response_data == NULL) {
                    response_data = malloc(evt->data_len + 1);
                    if (response_data == NULL) {
                        ESP_LOGE(TAG, "Failed to allocate memory for response");
                        return ESP_FAIL;
                    }
                    memcpy(response_data, evt->data, evt->data_len);
                } else {
                    char *temp = realloc(response_data, total_len + evt->data_len + 1);
                    if (temp == NULL) {
                        ESP_LOGE(TAG, "Failed to allocate memory for response");
                        free(response_data);
                        return ESP_FAIL;
                    }
                    response_data = temp;
                    memcpy(response_data + total_len, evt->data, evt->data_len);
                }
                total_len += evt->data_len;
                response_data[total_len] = 0; 
                ESP_LOGI(TAG, "Total responce length : %d",total_len);
            }
            break;
        case HTTP_EVENT_DISCONNECTED:
           ESP_LOGI(TAG, "HTTP_EVENT_DISCONNETED");
           if (response_data != NULL) {
                //ESP_LOGI(TAG, "Response: %s", response_data);
                cJSON *json_response = cJSON_Parse(response_data);
                if (json_response == NULL) {
                    ESP_LOGE(TAG, "Failed to parse JSON response");
                    myConfig->token_error = true;
                } else {
                    cJSON *nameItem = cJSON_GetObjectItem(json_response, "access_token");
                    if (nameItem != NULL && cJSON_IsString(nameItem)) {
                        myConfig->Access_Token = cJSON_GetStringValue(nameItem);
                        ESP_LOGI(TAG, "Acces Token parsed");
                    } else {
                        ESP_LOGE(TAG, "Can't find access_token item");
                    }
                    cJSON_Delete(json_response);
                    myConfig->token_ready = true;
                    ESP_LOGI(TAG, "Token parsed");
                }
                free(response_data);
                response_data = NULL;
                total_len = 0;
            }
            break;
        case HTTP_EVENT_HEADERS_SENT: 
            ESP_LOGI(TAG, "HTTP_EVENT_HEADERS_SENT");
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
        break;
        default: 
            ESP_LOGI(TAG, "Unhandled event: %d", evt->event_id);
            break;
        }
    return ESP_OK;
}
void exchangeJwtForAccessToken(JWTConfig *myConfig) {
    esp_http_client_config_t config = {
        .url = googleapis_auth_url,
        .event_handler = _http_event_handler,
        .cert_pem = cacert, 
        .user_data = myConfig
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    char post_data[1024];
    snprintf(post_data, sizeof(post_data), 
             "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s", myConfig->jwt_components.jwt);

    //ESP_LOGI(TAG, "Http POST DATA:%s",post_data);

    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");

    ESP_LOGI(TAG,"HTTP POST request...");    

    esp_err_t err = esp_http_client_perform(client);

    if (err != ESP_OK) {  
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    
    if(err != ESP_OK){
        free(myConfig->jwt_components.jwt);
        return;
    }
    while(!((myConfig->token_ready) | (myConfig->token_error)));
    free(myConfig->jwt_components.jwt);
    myConfig->step = step_valid_token_generated;
}

