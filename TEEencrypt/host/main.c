#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define CAESAR_ENCRYPT 0
#define CAESAR_DECRYPT 1
#define RSA_ENCRYPT 2

struct ta_attributes {
	TEEC_Context ctx;
	TEEC_Session sess;
};

int getTEEOption(int argumentCount, char* argv[]) {
	if (argumentCount < 3 || 4 < argumentCount) {
		printf("wrong argument count\n");
		exit(-1);	
	}

	if (argumentCount == 3) {
		if (strcmp("-e", argv[1]) == 0) {
			return CAESAR_ENCRYPT; 
		}

		if (strcmp("-d", argv[1]) == 0) {
			return CAESAR_DECRYPT;
		}
	}

	if (argumentCount == 4) {
		if (strcmp("Caesar", argv[3]) == 0) {
			if (strcmp("-e", argv[1]) == 0) {
				return CAESAR_ENCRYPT;
			}
		}

		if (strcmp("RSA", argv[3]) == 0) {
			if (strcmp("-e", argv[1]) == 0) {
				return RSA_ENCRYPT;
			}
		}
		
		printf("wrong option");
		exit(-1);
	}

}


void prepare_ta_session(struct ta_attributes *ta)
{
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ta->ctx);

	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);	
}

void terminate_tee_session(struct ta_attributes *ta)
{
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}

void prepare_op(TEEC_Operation *op, char *text, size_t text_size, char *out, size_t out_size) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = text;
	op->params[0].tmpref.size = text_size;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = out_size;
}

void rsa_generate_key(struct ta_attributes *ta) {
	TEEC_Result res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_RSA_KEY_GET, NULL, NULL);
}

void rsa_encrypt(struct ta_attributes *ta, char *text, size_t text_size, char *out, size_t out_size)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	prepare_op(&op, text, text_size, out, out_size);

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_RSA_ENCRYPT,
				&op, &origin);
}


int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	int textLength = 1000;
	char encryptedRandomKey[3];
	char plain[1000] = {0,};
	char cipher[1000] = {0,};
	
	int fd;
	
	struct ta_attributes ta;


	int teeOption = getTEEOption(argc, argv);
	
	if (teeOption == CAESAR_ENCRYPT) {
		printf("caesar encrypt\n");
		
        	res = TEEC_InitializeContext(NULL, &ctx);

        	res = TEEC_OpenSession(&ctx, &sess, &uuid,
                               TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

		fd = open(argv[2], O_RDONLY);
		
		if (fd == -1) {
			printf("file open failed");
			return -1;
		}

		read(fd, plain, textLength);
		close(fd);


		// Set param
		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plain;
		op.params[0].tmpref.size = textLength;
	
		memcpy(op.params[0].tmpref.buffer, plain, textLength);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
						 &err_origin);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_RANDOMKEY, &op,
						 &err_origin);

		memcpy(cipher, op.params[0].tmpref.buffer, textLength);
	
		encryptedRandomKey[0] = op.params[1].value.a;
		encryptedRandomKey[1] = '\0';
		strcat(cipher, encryptedRandomKey);

		if((fd = creat("./cipher.txt", 0644)) > 0){
			write(fd, cipher, strlen(cipher));
			close(fd);
		} else {
			printf("file write failed");
			return -1;
		}

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	}

	if (teeOption == CAESAR_DECRYPT) {
		res = TEEC_InitializeContext(NULL, &ctx);

		res = TEEC_OpenSession(&ctx, &sess, &uuid,
					       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		
		fd = open(argv[2], O_RDONLY);
		
		if(fd == -1){
			printf("fail");
			return -1;
		}
		
		read(fd, cipher, textLength);
		close(fd);
			

		// Set param
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
							 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = cipher;
		op.params[0].tmpref.size = textLength;
		memcpy(op.params[0].tmpref.buffer, cipher, textLength);	

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_RANDOMKEY, &op,
						 &err_origin);
		

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
						 &err_origin);

		memcpy(plain, op.params[0].tmpref.buffer, textLength);
	
			
		if ((fd = creat("./plain.txt", 0644)) > 0) {
			write(fd, plain, strlen(plain));						            close(fd);
		} else {
			printf("fail");
			return -1;
		}
		

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	}

	if (teeOption == RSA_ENCRYPT) {
		prepare_ta_session(&ta);

		fd = open(argv[2], O_RDONLY);

		if(fd == -1){
			printf("fail");
			return 1;	
		}		

		read(fd, plain, 1000);
		close(fd);

		rsa_generate_key(&ta);
		rsa_encrypt(&ta, plain, 1000, cipher, 1000);
			
		if((fd = creat("./cipher.txt", 0644)) > 0){
			write(fd, cipher, strlen(cipher));
			close(fd);
		} else {
			return -1;
		}
		
		terminate_tee_session(&ta);
	}


	return 0;
}
