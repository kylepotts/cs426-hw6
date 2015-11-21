genAES(){
   openssl enc -aes-256-cbc -k secret -P -md sha1 -nosalt | head -n 1 | cut -c 5- > aes.key
}

genAES
