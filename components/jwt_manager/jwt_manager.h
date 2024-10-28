#ifndef JWT_MANAGER_H
#define JWT_MANAGER_H
#include <math.h> 
#include <time.h>

#define MBEDTLS_BASE64_ENCODE_OUTPUT(length) ((((length) + 2) / 3) * 4 + 1)
#define CREATE_CHAR_BUFFER(size) ((char *)malloc(size))

static const char base64EncBuf[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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

typedef struct {
    char *header;
    char *payload;
    char *encHeader;
    char *encPayload;
    char *encHeadPayload;
    char *encSignature;
    char *signature;
    char *jwt;
    const char *private_key;
    const char *client_email;
    size_t signatureSize;
    char *hash;
    size_t hashSize;
} JWTConfig;

void concatStrings(char **str1, char *str2);
JWTConfig *new_JWTConfig();
char* exchangeJwtForAccessToken(const char* signed_jwt);
void jwt_encoded_genrate_header(JWTConfig *myConfig);
void jwt_encoded_genrate_payload(JWTConfig *myConfig);
void jwt_gen_hash(JWTConfig *myConfig);
void sign_jwt(JWTConfig *myConfig);
static time_t getTime();

#endif // JWT_MANAGER_H
