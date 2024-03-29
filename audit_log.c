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
char *curLogName;
int curLogIndex = 0;
char curSecret[32];
char curIV[32];
char curHashChainValue[32];

FILE* out_file;
int is_in_verify_all = -1;

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
    aes_file_name[strlen(curLogName)] = '\0';
    strncat(aes_file_name, "_aes", strlen(curLogName)+ 4);
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
    aes_file_name[strlen(curLogName)] = '\0';
    strncat(aes_file_name, "_aes", strlen(curLogName)+ 4);
    FILE* aes_file = fopen(aes_file_name, "r");
    unsigned char key[AESKEYLENGTH];
    unsigned char iv[IVLENGTH];
    if ( aes_file == NULL ){
	printf("null\n");
    }
    fread(key,sizeof(char),AESKEYLENGTH,aes_file);
    fread(iv,sizeof(char),IVLENGTH,aes_file);
    fclose(aes_file);


    unsigned char k[32];
    for(int i=0; i<=index; i++){
         SHA256(key,32,key);
    }
    char decyrpted_text [200];
    int decyrpted_text_len = decrypt(ciphertext, ciphertext_len, key,iv,decyrpted_text);
    decyrpted_text[decyrpted_text_len] = '\0';
    if(is_in_verify_all != 1){
    printf("%s\n", decyrpted_text);
    }
    else if(is_in_verify_all == 1 && out_file != NULL){
        fwrite(decyrpted_text,sizeof(char),decyrpted_text_len,out_file);
        fwrite("\n",sizeof(char),1,out_file);
    }
}

void create_close_entry(){
    char new_secret[32];
    SHA256(curSecret,32,new_secret);
    memset(curSecret,0,32);
    memcpy(curSecret,new_secret,32);

    unsigned char ciphertext[128];
    char str[] = "Log file close";
    int ciphertext_len = encrypt(str, strlen((char*)str), curSecret,curIV,ciphertext);


    unsigned char newHashChainValue[32];

    unsigned char hashString[400];


    char ent[] = "2";


    memcpy(hashString,curHashChainValue,32);
    memcpy(&hashString[32],ciphertext,ciphertext_len);
    memcpy(&hashString[32+16],ent,1);


    SHA256(hashString,32,newHashChainValue);
    memset(curHashChainValue,0,32);
    memcpy(curHashChainValue,newHashChainValue,32);

    unsigned char* digest;
    digest = HMAC(EVP_sha256(),curSecret,32,(unsigned char*)curHashChainValue,32,NULL,NULL);

    int total_len = 1+ciphertext_len+32+32;
    fseek(curLog,0,SEEK_END);
    fwrite(&total_len,sizeof(int),1,curLog);
    fwrite(&ciphertext_len,sizeof(int),1,curLog);
    fwrite(ciphertext,sizeof(char),ciphertext_len,curLog);
    fwrite(curHashChainValue,sizeof(char),32,curLog);
    fwrite(digest,sizeof(char),32,curLog);
    fwrite(ent,sizeof(char),1,curLog);
    fflush(curLog);
    curLogIndex++;

}

void create_open_entry(aes_pair* pair){
    // This is K_j
    SHA256(pair->key,32, curSecret);
    //printf("enc_key\n");
    //BIO_dump_fp(stdout, enc_key,32);

   // printf("iv\n");
    //BIO_dump_fp(stdout,pair->iv,IVLENGTH);

    unsigned char* message_text = (unsigned char*)"Log file opened";

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

    char log_entry[total_len];

    fwrite(&total_len,sizeof(int),1,curLog);
    fwrite(&ciphertext_len, sizeof(int),1, curLog);
    fwrite(ciphertext, sizeof(char),ciphertext_len,curLog);
    fwrite(y,sizeof(char),32,curLog);
    fwrite(digest,sizeof(char),32,curLog);
    fwrite(ent,sizeof(char),1,curLog);;
    fflush(curLog);
    curLogIndex = 1;

}


void handle_create_log(char* cmd){
    curLogName = (char*)malloc(sizeof(char)*100);
    char cmd_name[strlen(cmd)];
    sscanf(cmd, "%s %s", cmd_name, curLogName);
    if(curLog != NULL ){
        printf("Another log File is currently opened\n");
        return;
    }else {
        curLog = fopen(curLogName,"wb+");
        aes_pair* pair = generateAESKeyandIVForLog();
        create_open_entry(pair);
    }

}

void handle_close_log(){
    if(curLog == NULL){
        printf("Not log file is currently opened\n");
    } else {
        create_close_entry();
        fwrite(&curLogIndex,sizeof(int),1,curLog);
        memset(curLogName,0,100);
        curLogIndex = 1;
        memset(curSecret,0,32);
        memset(curIV,0,32);
        memset(curHashChainValue,32,0);

         fclose(curLog);
         curLog = NULL;
         curLogName = NULL;
    }
}

void handle_verify(char* cmd){
     char cmd_name[strlen(cmd)];
     char indexStr[strlen(cmd)];
     sscanf(cmd, "%s %s", cmd_name, indexStr);
     int index = atoi(indexStr);

     FILE* log_file = fopen(curLogName,"r");

    if ( log_file == NULL ){
	printf("Error opening log file\n");
	return;
    }
    rewind(log_file);
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
        fread(&log_length, sizeof(int),1,log_file);
        if(log_length < 0 || log_length > 1000000){
            if(is_in_verify_all != 1){
                printf("Failed Verification\n");
                return;
            }else {
                printf("Fail\n");
                fwrite("Failed Verification\n",sizeof(char),strlen("Failed Verification\n"),out_file);
                return;
            }

        }
        fread(&ciphertext_len, sizeof(int),1,log_file);
        if(ciphertext_len < 0 || ciphertext_len > 10000000){
            if(is_in_verify_all != 1){
                printf("Failed Verification\n");
                return;
            }else {
                fwrite("Failed Verification\n",sizeof(char),strlen("Failed Verification\n"),out_file);
                return;
            }

        }

        ciphertext = (char*)malloc(sizeof(char)*ciphertext_len);
        fread(ciphertext,sizeof(char),ciphertext_len,log_file);
        fread(current_log_y,sizeof(char),32,log_file);
        fread(z,sizeof(char),32,log_file);
        fread(&ent,sizeof(char),1,log_file);
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
    if(memcmp(current_log_y,y,32) == 0){
        get_log_data(index,ent, ciphertext, ciphertext_len);
    }
    else{
        if(is_in_verify_all != 1){
             printf("Failed Verification\n");
        }else {
            fwrite("Failed Verification\n",sizeof(char),strlen("Failed Verification\n"),out_file);
        }
    }
    fclose(log_file);
}


void handle_add_message(char* cmd){
    if ( curLog == NULL ){
	printf("Cannot add message\n");
	return;
    }
    char cmd_name[100];
    char str[100];
    sscanf(cmd,"%s %[^\t\n]", cmd_name, str);

    char new_secret[32];
    SHA256(curSecret,32,new_secret);
    memset(curSecret,0,32);
    memcpy(curSecret,new_secret,32);

    unsigned char ciphertext[128];

    int ciphertext_len = encrypt(str, strlen((char*)str), curSecret,curIV,ciphertext);


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

    /*
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
    */

    int total_len = 1+ciphertext_len+32+32;
    fseek(curLog,0,SEEK_END);
    fwrite(&total_len,sizeof(int),1,curLog);
    fwrite(&ciphertext_len,sizeof(int),1,curLog);
    fwrite(ciphertext,sizeof(char),ciphertext_len,curLog);
    fwrite(curHashChainValue,sizeof(char),32,curLog);
    fwrite(digest,sizeof(char),32,curLog);
    fwrite(ent,sizeof(char),1,curLog);
    //fwrite(log_entry,sizeof(char),82,curLog);
    fflush(curLog);
    printf("Added log entry number %d\n",curLogIndex);
    curLogIndex++;
}

void handle_verify_all(char* cmd){
    char cmd_name[100];
    curLogName = (char*)malloc(sizeof(char)*100);
    char out_name[100];
    sscanf(cmd,"%s %s %s", cmd_name,curLogName,out_name);

    curLog = fopen(curLogName,"r");
    if(curLog == NULL){
        printf("Error opening log\n");
        exit(-1);
    }


    out_file = fopen(out_name,"w+");
    if(out_file == NULL){
        printf("Error opening out file\n");
        exit(-1);
    }

    int fileSize = 0;
    fseek(curLog,0,SEEK_END);
    fileSize = ftell(curLog);
    fseek(curLog,fileSize-sizeof(int),SEEK_SET);

    int nEntries;
    fread(&nEntries, sizeof(int),1,curLog);
    if(nEntries > 100000){
        fwrite("Failed Verification\n", sizeof(char),strlen("Failed Verification\n"), out_file);
        return;
    }
    rewind(curLog);

    is_in_verify_all = 1;

    for(int i=0; i<nEntries; i++){
        char cmd[100];
        sprintf(cmd, "verify %d",i);
        handle_verify(cmd);
    }
    fflush(out_file);
    fclose(out_file);
    out_file = NULL;
    is_in_verify_all = -1;
    fclose(curLog);
    curLog = NULL;
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
        else if(strncmp(cmd,"verify",6) == 0 && strncmp(cmd,"verifyall",9) != 0){
             handle_verify(cmd);
        }
        else if(strncmp(cmd,"add",3) == 0){
             handle_add_message(cmd);
        }
        else if(strncmp(cmd,"verifyall",9) == 0){
             handle_verify_all(cmd);
        }
        else {
             printf("Invalid command\n");
        }
    }
}



