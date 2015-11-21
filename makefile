
all: audit_log

audit_log: audit_log.c audit_log.h
	gcc -std=c99 -lssl -lcrypto -o audit_log audit_log.c

clean: 
	rm audit_log tylor tylor_aes
