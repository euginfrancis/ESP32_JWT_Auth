/**
 * jwt_manager.h
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
#ifndef JWT_MANAGER_H
#define JWT_MANAGER_H
#include <math.h> 
#include <time.h>
#include "esp_err.h"
#include "esp_http_client.h"
#include "cJSON.h"

#define MBEDTLS_BASE64_ENCODE_OUTPUT(len) ((((len) + 2) / 3 * 4) + 1)
#define CREATE_CHAR_BUFFER(size) ((char *)malloc(size)) 
#define ERROR_BUFFER_SIZE 100

static const char base64EncBuff[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char googleapis_auth_url[] = "https://www.googleapis.com/oauth2/v4/token";
static const char googleapis_auth2_url[] = "https://oauth2.googleapis.com/token";
static const char googleapis_scope_url[] = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email";
static const char esp_signer_gauth_pgm_str_1[]  = "type";
static const char esp_signer_gauth_pgm_str_2[]  = "service_account";
static const char esp_signer_gauth_pgm_str_3[]  = "project_id";
static const char esp_signer_gauth_pgm_str_4[]  = "private_key_id";
static const char esp_signer_gauth_pgm_str_5[]  = "private_key";
static const char esp_signer_gauth_pgm_str_6[]  = "client_email";
static const char esp_signer_gauth_pgm_str_7[]  = "client_id";
static const char esp_signer_gauth_pgm_str_8[]  = "securetoken";
static const char esp_signer_gauth_pgm_str_9[]  = "grantType";
static const char esp_signer_gauth_pgm_str_10[]  = "refresh_token";
static const char esp_signer_gauth_pgm_str_11[]  = "refreshToken";
static const char esp_signer_gauth_pgm_str_12[]  = "/v1/token?Key=";
static const char esp_signer_gauth_pgm_str_13[]  = "application/json";
static const char esp_signer_gauth_pgm_str_14[]  = "error/code";
static const char esp_signer_gauth_pgm_str_15[]  = "error/message";
static const char esp_signer_gauth_pgm_str_16[]  = "id_token";
static const char esp_signer_gauth_pgm_str_18[]  = "refresh_token";
static const char esp_signer_gauth_pgm_str_19[]  = "expires_in";
static const char esp_signer_gauth_pgm_str_20[]  = "alg";
static const char esp_signer_gauth_pgm_str_21[]  = "RS256";
static const char esp_signer_gauth_pgm_str_22[]  = "typ";
static const char esp_signer_gauth_pgm_str_23[]  = "JWT";
static const char esp_signer_gauth_pgm_str_24[]  = "iss";
static const char esp_signer_gauth_pgm_str_25[]  = "sub";
static const char esp_signer_gauth_pgm_str_26[]  = "https://";
static const char esp_signer_gauth_pgm_str_27[]  = "oauth2";
static const char esp_signer_gauth_pgm_str_28[]  = "/";
static const char esp_signer_gauth_pgm_str_29[]  = "token";
static const char esp_signer_gauth_pgm_str_31[]  = "iat";
static const char esp_signer_gauth_pgm_str_32[]  = "exp";
static const char esp_signer_gauth_pgm_str_33[]  = "scope";
static const char esp_signer_gauth_pgm_str_35[]  = ".";
static const char esp_signer_gauth_pgm_str_36[]  = "www";
static const char esp_signer_gauth_pgm_str_37[]  = "client_secret";
static const char esp_signer_gauth_pgm_str_39[]  = "urn:ietf:params:oauth:grant-type:jwt-bearer";
static const char esp_signer_gauth_pgm_str_40[]  = "assertion";
static const char esp_signer_gauth_pgm_str_41[]  = "oauth2";
static const char esp_signer_gauth_pgm_str_43[]  = "error_description";
static const char esp_signer_gauth_pgm_str_44[]  = "access_token";
static const char esp_signer_gauth_pgm_str_45[]  = "Bearer ";
static const char esp_signer_gauth_pgm_str_46[]  = "https://www.googleapis.com/auth/cloud-platform";
static const char esp_signer_gauth_pgm_str_47[]  =  "aud";

static const char esp_signer_pgm_str_1[]  = "\r\n";
static const char esp_signer_pgm_str_2[]  = ".";
static const char esp_signer_pgm_str_3[]  = "googleapis.com";
static const char esp_signer_pgm_str_4[]  = "Host: ";
static const char esp_signer_pgm_str_5[]  = "Content-Type: ";
static const char esp_signer_pgm_str_6[]  = "Content-Length: ";
static const char esp_signer_pgm_str_7[]  = "User-Agent: ESP\r\n";
static const char esp_signer_pgm_str_8[]  = "Connection: keep-alive\r\n";
static const char esp_signer_pgm_str_9[]  = "Connection: close\r\n";
static const char esp_signer_pgm_str_10[]  = "GET";
static const char esp_signer_pgm_str_11[]  = "POST";
static const char esp_signer_pgm_str_12[]  = "PATCH";
static const char esp_signer_pgm_str_13[]  = "DELETE";
static const char esp_signer_pgm_str_14[]  = "PUT";
static const char esp_signer_pgm_str_15[]  = " ";
static const char esp_signer_pgm_str_16[]  = " HTTP/1.1\r\n";
static const char esp_signer_pgm_str_17[]  = "Authorization: ";
static const char esp_signer_pgm_str_18[]  = "Bearer ";
static const char esp_signer_pgm_str_19[]  = "true";
static const char esp_signer_pgm_str_20[]  = "Connection: ";
static const char esp_signer_pgm_str_21[]  = "Content-Type: ";
static const char esp_signer_pgm_str_22[]  = "Content-Length: ";
static const char esp_signer_pgm_str_23[]  = "ETag: ";
static const char esp_signer_pgm_str_24[]  = "Transfer-Encoding: ";
static const char esp_signer_pgm_str_25[]  = "chunked";
static const char esp_signer_pgm_str_26[]  = "Location: ";
static const char esp_signer_pgm_str_27[]  = "HTTP/1.1 ";
static const char esp_signer_pgm_str_28[]  = "?";
static const char esp_signer_pgm_str_29[]  = "&";
static const char esp_signer_pgm_str_30[]  = "=";
static const char esp_signer_pgm_str_31[]  = "/";
static const char esp_signer_pgm_str_32[]  = "https://";
static const char esp_signer_pgm_str_33[]  = "https://%[^/]/%s";
static const char esp_signer_pgm_str_34[]  = "http://%[^/]/%s";
static const char esp_signer_pgm_str_35[]  = "%[^/]/%s";
static const char esp_signer_pgm_str_36[]  = "%[^?]?%s";
static const char esp_signer_pgm_str_37[]  = "auth=";
static const char esp_signer_pgm_str_38[]  = "%[^&]";
static const char esp_signer_pgm_str_39[]  = "undefined";
static const char esp_signer_pgm_str_40[]  = "OAuth2.0 access token";
static const char esp_signer_pgm_str_41[]  = "uninitialized";
static const char esp_signer_pgm_str_42[]  = "on initializing";
static const char esp_signer_pgm_str_43[]  = "on signing";
static const char esp_signer_pgm_str_44[]  = "on exchange request";
static const char esp_signer_pgm_str_45[]  = "on refreshing";
static const char esp_signer_pgm_str_46[]  = "error";
static const char esp_signer_pgm_str_47[]  = "code: ";
static const char esp_signer_pgm_str_48[]  = ", message: ";
static const char esp_signer_pgm_str_49[]  = "ready";

typedef enum{
    step_jwt_encoded_genrate_header,
    step_jwt_encoded_genrate_payload,
    step_jwt_gen_hash,
    step_sign_jwt,
    step_exchangeJwtForAccessToken,
    step_valid_token_generated
}jwt_generation_steps;

typedef struct{
    char *header;
    char *payload;
    char *encHeader;
    char *encPayload;
    char *encHeadPayload;
    char *encSignature;
    char *signature;
    char *jwt;
    char *hash;
}JWTComponents;

typedef struct JWTConfig{
    JWTComponents jwt_components;
    bool token_ready;
    bool token_error;
    bool time_sync_finished;
    const char *private_key;
    const char *client_email;
    const char *Access_Token;
    size_t signatureSize;
    size_t hashSize;
    void (*init_JWT_Auth)(struct JWTConfig*);
    jwt_generation_steps step;
} JWTConfig;

void init_JWT_Auth(JWTConfig *myConfig);
static bool concatStrings(char **str1, char *str2);
JWTConfig *new_JWTConfig();
void exchangeJwtForAccessToken(JWTConfig *myConfig);
void jwt_encoded_genrate_header(JWTConfig *myConfig);
void jwt_encoded_genrate_payload(JWTConfig *myConfig);
void jwt_gen_hash(JWTConfig *myConfig);
void sign_jwt(JWTConfig *myConfig);
static time_t getTime();
static bool encodeUrl(char *encoded, unsigned char *string, size_t len);
static esp_err_t _http_event_handler(esp_http_client_event_t *evt);
int mbedtls_error_log(int error);

#endif 
