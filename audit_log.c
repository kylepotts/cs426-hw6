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
int curLogIndex = 0;
char curSecret[32];
char curIV[32];
char curHashChainValue[32];

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
    fwrite(key,sizeof(char),AESKEYLENGTH,aes_file);
    fwrite(iv,sizeof(char),IVLENGTH,aes_file);
    fflush(aes_file);
    fclose(aes_file);

    aes_pair* pair = (aes_pair*)malloc(sizeof(aes_pair));
    pair->key = key;
    pair->iv = iv;


    memset(curIV,0,IVLENGTH);
    memcpy(curIV,iv,IVLENGTH);
    return pair;


}

void get_log_data(int index, char  ent, unsigned char*ciphertext, int ciphertext_len){
    char aes_file_name[200];
    strncpy(aes_file_name,curLogName,strlen(curLogName));
    strncat(aes_file_name, "_aes", strlen(aes_file_name)+ 4);
    FILE* aes_file = fopen(aes_file_name, "r");
    unsigned char key[AESKEYLENGTH];
    unsigned char iv[IVLENGTH];
    fread(key,sizeof(char),AESKEYLENGTH,aes_file);
    fread(iv,sizeof(char),IVLENGTH,aes_file);
    fclose(aes_file);

    unsigned char deckey[32];
    SHA256(key,32,deckey);
    //printf("dec_key\n");
   // BIO_dump_fp(stdout,deckey,32);

    //printf("IV\n");
    //BIO_dump_fp(stdout,iv,IVLENGTH);


    for(int i=1; i<index; i++){
         SHA256(key,32,key);
    }
    char decyrpted_text [200];
    int decyrpted_text_len = decrypt(ciphertext, ciphertext_len, deckey,iv,decyrpted_text);
    decyrpted_text[decyrpted_text_len] = '\0';
    printf("text=%s\n", decyrpted_text);
}



void create_open_entry(aes_pair* pair){
    // This is K_j
    SHA256(pair->key,32, curSecret);
    //printf("enc_key\n");
    //BIO_dump_fp(stdout, enc_key,32);

   // printf("iv\n");
    //BIO_dump_fp(stdout,pair->iv,IVLENGTH);

    unsigned char* message_text = (unsigned char*)"log file opened";

    unsigned char ciphertext[128];

    int ciphertext_len;


    ciphertext_len = encrypt(message_text, strlen((char*)message_text), curSecret,pair->iv,ciphertext);
    //printf("ciphertext\n");
    //BIO_dump_fp(stdout, ciphertext, ciphertext_len);
    char ent [10];
    sprintf(ent, "%d", OPEN_ENTRY);

    //printf("y_j\n");

    char* m = "INIT";
    char inital_hash[32];
    SHA256(m,strlen(m),inital_hash);


    char hashItems[32+16+1];
    memset(hashItems,0,49);
    memcpy(hashItems,inital_hash,32);
    memcpy(&hashItems[32],ciphertext,16);
    memcpy(&hashItems[32+16],"0",1);

    char y[32];
    SHA256(hashItems,32,y);

    memcpy(curHashChainValue,y,32);


    unsigned char* digest;
    digest = HMAC(EVP_sha256(),curSecret,32,(unsigned char*)y,32,NULL,NULL);
    //printf("digest\n");
    //BIO_dump_fp(stdout, digest,32);

    int ent_len = 1; // 1
    int enc_data_len = ciphertext_len; //16
    int hash_len = 32; // 33
    int digest_len = 32; // 32
    int total_len = ent_len+enc_data_len+hash_len+digest_len;
    printf("total_len=%d\n", total_len);

    char log_entry[total_len];
    /*
    log_entry[0] = '\0';
    memcpy(log_entry,ent,1);
    memcpy(&log_entry[1],&ciphertext_len,sizeof(int));
    memcpy(&log_entry[1+sizeof(int)],ciphertext, ciphertext_len);
    memcpy(&log_entry[1+sizeof(int)+ciphertext_len],y,32);
    memcpy(&log_entry[1+sizeof(int)+ciphertext_len+32],digest,32);
    printf("Entry\n");
    BIO_dump_fp(stdout,log_entry,total_len);
    */

    //printf("ent=%d enc_data=%d hash=%d digest_len=%d\n", ent_len,enc_data_len, hash_len,digest_len);
    fwrite(&total_len,sizeof(int),1,curLog);
    fwrite(&ciphertext_len, sizeof(int),1, curLog);
    fwrite(ciphertext, sizeof(char),ciphertext_len,curLog);
    fwrite(y,sizeof(char),32,curLog);
    fwrite(digest,sizeof(char),32,curLog);
    fwrite(ent,sizeof(char),1,curLog);;
    fflush(curLog);
    curLogIndex++;

}


void handle_create_log(char* cmd){
    char cmd_name[strlen(cmd)];
    sscanf(cmd, "%s %s", cmd_name, curLogName);
    if(curLog != NULL ){
        printf("Another log File is currently opened\n");
        return;
    }else {
        curLog = fopen(curLogName,"wb+");
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

void handle_verify(char* cmd){
     char cmd_name[strlen(cmd)];
     char indexStr[strlen(cmd)];
     sscanf(cmd, "%s %s", cmd_name, indexStr);
     int index = atoi(indexStr);
     printf("index=%d\n", index);

    rewind(curLog);
    unsigned char log[82];

    char* m = "INIT";
    char y[32];
    char z[32];
    char current_log_y[32];
    char ent;
    SHA256(m,strlen(m),y);
    char* ciphertext;
    int ciphertext_len;


    for(int i=0; i<=index; i++){
        int log_length;
        fread(&log_length, sizeof(int),1,curLog);
        printf("Log length=%d\n",log_length);
        fread(&ciphertext_len, sizeof(int),1,curLog);
        printf("ciphertext_len=%d\n",ciphertext_len);

        ciphertext = (char*)malloc(sizeof(char)*ciphertext_len);
        fread(ciphertext,sizeof(char),ciphertext_len,curLog);
        fread(current_log_y,sizeof(char),32,curLog);
        fread(z,sizeof(char),32,curLog);
        fread(&ent,sizeof(char),1,curLog);

        char hashItems[32+ciphertext_len+1];
        char h[32];
        memset(hashItems,0,32+ciphertext_len+1);
        memcpy(hashItems,y,32);
        memcpy(&hashItems[32],ciphertext,ciphertext_len);
        memcpy(&hashItems[32+ciphertext_len],&ent,1);
        SHA256(hashItems,32,h);
        memcpy(y,h,32);



        /*
        unsigned char l[82];
        memcpy(l,log,82);

        char z[32];
        memcpy(&ent,&log[0],1);
        memcpy(ciphertext, &log[1], 16);
        memcpy(current_log_y,&log[1+16],33);
        memcpy(z,&log[1+16+32+1],32);



        char hashItems[49];
        char h[32];
        memset(hashItems,0,49);
        memcpy(hashItems,y,32);
        memcpy(&hashItems[32],ciphertext,16);
        memcpy(&hashItems[32+16],&ent,1);

        SHA256(hashItems,32,h);
        memcpy(y,h,32);

        //printf("hhh\n");
        //BIO_dump_fp(stdout,y,32);
        */

    }
    printf("current_log_y\n");
    BIO_dump_fp(stdout,current_log_y,32);
    printf("y!\n");
    BIO_dump_fp(stdout,y,32);
    if(memcmp(current_log_y,y,32) == 0){
        printf("same hash!\n");
        get_log_data(index,ent, ciphertext, ciphertext_len);

    }
}


void handle_add_message(char* cmd){
    char cmd_name[100];
    char str[100];
    sscanf(cmd,"%s %s", cmd_name, str);
    printf("str=%s\n",str);

    char new_secret[32];
    SHA256(curSecret,32,new_secret);
    memset(curSecret,0,32);
    memcpy(curSecret,new_secret,32);

    unsigned char ciphertext[128];

    int ciphertext_len = encrypt(str, strlen((char*)str), curSecret,curIV,ciphertext);
    printf("len=%d\n",ciphertext_len);


    unsigned char newHashChainValue[32];

    unsigned char hashString[400];


    char ent[] = "1";
    //sprintf(ent, "%d",NORMAL_ENTRY);
    //printf("old hash value\n");
    //BIO_dump_fp(stdout,curHashChainValue,32);


    memcpy(hashString,curHashChainValue,32);
    memcpy(&hashString[32],ciphertext,ciphertext_len);
    memcpy(&hashString[32+16],ent,1);


    SHA256(hashString,32,newHashChainValue);
    memset(curHashChainValue,0,32);
    memcpy(curHashChainValue,newHashChainValue,32);
    //printf("new hash value\n");
    //BIO_dump_fp(stdout,curHashChainValue,32);

    unsigned char* digest;
    digest = HMAC(EVP_sha256(),curSecret,32,(unsigned char*)curHashChainValue,32,NULL,NULL);


    char log_entry[82];
    log_entry[0] = '\0';
    memcpy(log_entry,ent,1);
    memcpy(&log_entry[1],ciphertext, ciphertext_len);
    memcpy(&log_entry[1+ciphertext_len],curHashChainValue,32);
    memcpy(&log_entry[1+ciphertext_len+32],digest,32);

    printf("length=%d\n",ciphertext_len);
    BIO_dump_fp(stdout, ciphertext,ciphertext_len);
    printf("\n");


    BIO_dump_fp(stdout,log_entry,82);

    fseek(curLog,0,SEEK_END);
    fwrite(log_entry,sizeof(char),82,curLog);
    fflush(curLog);
    printf("Added log entry number %d\n",curLogIndex);
    curLogIndex++;





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
        else if(strncmp(cmd,"verify",6) == 0){
             handle_verify(cmd);
        }
        else if(strncmp(cmd,"add",3) == 0){
             handle_add_message(cmd);
        }
        else {
             printf("Invalid command\n");
        }
    }
}



