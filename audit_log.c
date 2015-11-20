#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<openssl/aes.h>
#include<openssl/rand.h>
#include<openssl/sha.h>
#include<openssl/conf.h>
#include<openssl/evp.h>
#include<openssl/err.h>
#include<openssl/hmac.h>

#define AESKEYLENGTH 32
#define IVLENGTH 16

FILE* curLog;
char curLogName[100];

struct aes_pair {
    unsigned char* key;
    unsigned char* iv;
};

typedef struct aes_pair aes_pair;

typedef enum {OPEN_ENTRY, NORMAL_ENTRY, CLOSE_ENTRY} entry_type;

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

 aes_pair* generateAESKeyandIVForLog(){
    unsigned char* key = (unsigned char*)malloc(AESKEYLENGTH);
    unsigned char* iv  = (unsigned char*)malloc(IVLENGTH);
    memset(key,0,AESKEYLENGTH);
    memset(iv,0,IVLENGTH);
    if(!RAND_bytes(key,AESKEYLENGTH)){
        printf("Error creating AES Key, Exiting\n");
        exit(-1);
    }
    key[AESKEYLENGTH-1] = '\0';

    if(!RAND_bytes(iv, IVLENGTH)){
        printf("Error create IV, Exiting");
        exit(-1);
    }
    iv[IVLENGTH-1] = '\0';

    char aes_file_name[200];
    strncpy(aes_file_name,curLogName,strlen(curLogName));
    strncat(aes_file_name, "_aes", strlen(aes_file_name)+ 4);
    FILE* aes_file = fopen(aes_file_name, "w+");
    fprintf(aes_file,"%s\n %s\n", key,iv);
    fclose(aes_file);

    aes_pair* pair = (aes_pair*)malloc(sizeof(aes_pair));
    pair->key = key;
    pair->iv = iv;
    return pair;


}

void create_open_entry(aes_pair* pair){
    char hashItems[100];
    sprintf(hashItems,"%d",OPEN_ENTRY);
    strcat(hashItems, pair->key);

    // This is Y_j
    char enc_key [32];
    SHA256(hashItems,strlen(hashItems), enc_key);

    unsigned char* message_text = (unsigned char*)"log file opened";

    unsigned char ciphertext[128];
    unsigned char plaintext[128];

    int ciphertext_len;
    ciphertext_len = encrypt(message_text, strlen((char*)message_text), enc_key,pair->iv,ciphertext);

    char otherHashItems [strlen("0000")+ciphertext_len+1];
    char ent [10];
    sprintf(ent, "%d", OPEN_ENTRY);
    strcat(otherHashItems,"0000");
    strcat(otherHashItems,ciphertext);
    strcat(otherHashItems,ent);

    // This is K_j
    char hash[32];
    SHA256(otherHashItems, strlen(otherHashItems),hash);

    unsigned char* digest;
    digest = HMAC(EVP_sha256(),pair->key,strlen(pair->key),(unsigned char*)enc_key,strlen(enc_key),NULL,NULL);

    int ent_len = strlen(ent); // 1
    int enc_data_len = ciphertext_len; //16
    int hash_len = strlen(hash); // 33
    int digest_len = strlen(digest); // 32

    char log_entry[ent_len+enc_data_len+hash_len+digest_len];
    log_entry[0] -'\0';
    strcat(log_entry,ent);
    strcat(log_entry,ciphertext);
    strcat(log_entry,hash);
    strcat(log_entry,digest);
    printf("log=%d\n",strlen(log_entry));

    printf("ent=%d enc_data=%d hash=%d digest_len=%d\n", ent_len,enc_data_len, hash_len,digest_len);








}


void handle_create_log(char* cmd){
    char cmd_name[strlen(cmd)];
    sscanf(cmd, "%s %s", cmd_name, curLogName);
    if(curLog != NULL ){
        printf("Another log File is currently opened\n");
        return;
    }else {
        curLog = fopen(curLogName,"a");
        aes_pair* pair = generateAESKeyandIVForLog();
        create_open_entry(pair);
        printf("Log with name %s sucessfully opened\n", curLogName);
    }

}

void handle_close_log(){
    if(curLog == NULL){
        printf("Not log file is currently opened\n");
    } else {
         fclose(curLog);
         printf("Log sucessfully closed\n");
         curLog = NULL;
    }
}

int main(){
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    char cmd[100];
    while(1){
        memset(cmd,0,100);
        printf("command> ");
        fgets(cmd,100,stdin);
        cmd[strlen(cmd)-1] = '\0';
        if(strcmp(cmd,"exit") == 0){
            break;
        }
        else if (strncmp(cmd,"createlog",9 ) == 0){
            handle_create_log(cmd);
        }
        else if(strcmp(cmd,"closelog") == 0){
             handle_close_log();
        }
        else {
             printf("Invalid command\n");
        }
    }
}



