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


static void encodeUrl(char *encoded, unsigned char *string, size_t len)
{
    size_t i;
    char *p = encoded;
    
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
}

static void concatStrings(char **str1, char *str2) {
    if(str2 == NULL){
        return;
    }
    
    size_t totalLength = strlen(*str1) + strlen(str2) + 1;
    char *combined = CREATE_CHAR_BUFFER(totalLength);

    if (combined == NULL) {
        return; 
    }
    strcpy(combined, *str1); 
    strcat(combined, str2);

    if(strlen(*str1) > 0){
        free(*str1);
    }
    *str1 = combined;
}

JWTConfig *new_JWTConfig() {
    return malloc(sizeof(JWTConfig));
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
    size_t output_length;
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

    cJSON_AddItemToObject(jsonPtr, "alg", cJSON_CreateString("RS256")); // "alg": "RS256"
    cJSON_AddItemToObject(jsonPtr, "typ", cJSON_CreateString("JWT"));   // "typ": "JWT"

    myConfig->header = cJSON_PrintUnformatted(jsonPtr);
    if (!myConfig->header) {
        ESP_LOGE(TAG, "Failed to print JSON");
        cJSON_Delete(jsonPtr);
        return;
    }

    myConfig->encHeader = base64_encode((unsigned char *)myConfig->header, strlen(myConfig->header));
    if (!myConfig->encHeader) {
        ESP_LOGE(TAG, "Failed to encode JSON to Base64");
        free(myConfig->header);
        cJSON_Delete(jsonPtr);
        return;
    }
    myConfig->encHeadPayload = myConfig->encHeader;
    ESP_LOGI(TAG, "Encoded Header: %s , %s", myConfig->encHeadPayload,myConfig->header);
    free(myConfig->header);
    cJSON_Delete(jsonPtr);
}

void jwt_encoded_genrate_payload(JWTConfig *myConfig){
    time_t now =  getTime(); 
    cJSON *jsonPtr = cJSON_CreateObject();

    if (!jsonPtr) {
        ESP_LOGE(TAG, "Failed to create JSON object");
        return;
    }

    cJSON_AddStringToObject(jsonPtr, "iss", myConfig->client_email);
    cJSON_AddStringToObject(jsonPtr, "sub", myConfig->client_email);

    cJSON_AddStringToObject(jsonPtr, "aud", "https://oauth2.googleapis.com/token");
    cJSON_AddNumberToObject(jsonPtr, "iat", (int)now);
    cJSON_AddNumberToObject(jsonPtr, "exp", (int)(now + 3600));
    cJSON_AddStringToObject(jsonPtr, "scope", "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email");

    myConfig->payload = cJSON_PrintUnformatted(jsonPtr); 
    myConfig->encPayload = base64_encode((unsigned char *)myConfig->payload, strlen(myConfig->payload));

    concatStrings(&myConfig->encHeadPayload,esp_signer_gauth_pgm_str_35);
    concatStrings(&myConfig->encHeadPayload,myConfig->encPayload);

    ESP_LOGI(TAG, "Encoded Payload: %s , %s", myConfig->payload,myConfig->encHeadPayload);

    free(myConfig->encPayload);  
    cJSON_Delete(jsonPtr); 
    return;
}

void jwt_gen_hash(JWTConfig *myConfig){
    myConfig->hash = CREATE_CHAR_BUFFER(myConfig->hashSize);
    if (myConfig->hash == NULL) {
        return;
    }
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); 
    mbedtls_sha256_update(&sha_ctx, (unsigned char *)myConfig->encHeadPayload, strlen(myConfig->encHeadPayload));
    mbedtls_sha256_finish(&sha_ctx, (unsigned char *)myConfig->hash);
    mbedtls_sha256_free(&sha_ctx);
}
int my_rng(void *ctx, unsigned char *output, size_t len) {
    return mbedtls_ctr_drbg_random((mbedtls_ctr_drbg_context *)ctx, output, len);
}

void sign_jwt(JWTConfig *myConfig){
    concatStrings(&myConfig->jwt,myConfig->encHeadPayload);
    free(myConfig->encHeadPayload);
    concatStrings(&myConfig->jwt,esp_signer_gauth_pgm_str_35);
    char error_buf[100];

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers="MyEntropy";

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func , &entropy, NULL, 0);
    if (ret != 0) {
        mbedtls_strerror(-ret, error_buf, sizeof(error_buf));
        ESP_LOGE(TAG,"Error: %s\n", error_buf); 
        return;
    }
    myConfig->signature = CREATE_CHAR_BUFFER(MBEDTLS_MPI_MAX_SIZE);
    if (myConfig->signature == NULL) {
        ESP_LOGE(TAG,"Can allocate memmory for signature"); 
        return;    
    }
    ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)myConfig->private_key, strlen(myConfig->private_key) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_strerror(-ret, error_buf, sizeof(error_buf));
        ESP_LOGE(TAG,"Error: %s\n", error_buf); 
        return;
    }

    ESP_LOGI(TAG, "Signing started");

    size_t sig_len;
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, (const unsigned char *)myConfig->hash,
                               myConfig->hashSize,  (unsigned char *)myConfig->signature,
                               myConfig->signatureSize,&sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        free(myConfig->signature); 
        mbedtls_strerror(-ret, error_buf, sizeof(error_buf));
        ESP_LOGE(TAG,"Error: %s\n", error_buf);         
        return;
    }

    myConfig->encSignature = base64_encode((unsigned char *)myConfig->signature,myConfig->signatureSize);
    free(myConfig->signature);
    concatStrings(&myConfig->jwt,myConfig->encSignature);
    ESP_LOGI(TAG, "JWT : %s",myConfig->jwt);
    return; 
}

static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    return ESP_OK;
}

char* exchangeJwtForAccessToken(const char* signed_jwt) {
    const char* auth_url = "https://www.googleapis.com/oauth2/v4/token";

    esp_http_client_config_t config = {
        .url = auth_url,
        .event_handler = _http_event_handler,
        .cert_pem = cacert, 
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    char post_data[512];
    snprintf(post_data, sizeof(post_data), 
             "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=%s", signed_jwt);

    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        
        ESP_LOGI(TAG, "HTTP Status = %d, content_length = %lld", 
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
        
        char* response = malloc(1024); 
        if (response) {
            esp_http_client_read(client, response, 1024);
            cJSON *json = cJSON_Parse(response);
            const cJSON *access_token = cJSON_GetObjectItemCaseSensitive(json, "access_token");
            char *token = NULL;
            if (cJSON_IsString(access_token) && (access_token->valuestring != NULL)) {
                token = strdup(access_token->valuestring); 
            }
            cJSON_Delete(json);
            free(response);
            esp_http_client_cleanup(client);
            return token; 
        }
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return NULL; 
}

