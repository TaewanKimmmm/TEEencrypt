#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>


unsigned int random_key;
int root_key = 7;

struct rsa_session {
	TEE_OperationHandle op_handle;	
	TEE_ObjectHandle key_handle; 
};

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;
	
	*sess_ctx = (void *)sess;

	IMSG("Hello World!\n");

	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result create_random_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	
	random_key %= 26;
	
	while(random_key == 0){
		TEE_GenerateRandom(&random_key, sizeof(random_key));
		random_key %= 26;
	}
	
	return TEE_SUCCESS;
}

static TEE_Result enc_random_key(uint32_t param_types,
	TEE_Param params[4])
{
	if('a' <= random_key && random_key <= 'z'){
		random_key -= 'a';
		random_key += root_key;
		random_key %= 26;
		random_key += 'a';
	}

	if ('A' <= random_key && random_key <= 'Z') {
		random_key -= 'A';
		random_key += root_key;
		random_key %= 26;
		random_key += 'A';
	}
	params[1].value.a = (uint32_t)random_key;
	return TEE_SUCCESS;
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * plain = (char *)params[0].memref.buffer;
	int plainLength = strlen (params[0].memref.buffer);

	char encrypted[1000] = {0,};

	memcpy(encrypted, plain, plainLength);
	
	for(int i = 0; i < plainLength; i++){
		if('a' <= encrypted[i] && encrypted[i] <= 'z'){
			encrypted[i] -= 'a';
			encrypted[i] += random_key;
			encrypted[i] %= 26;
			encrypted[i] += 'a';
		}

		if ('A' <= encrypted[i] && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += random_key;
			encrypted[i] %= 26;
			encrypted[i] += 'A';
		}
	}

	memcpy(plain, encrypted, plainLength);
	return TEE_SUCCESS;
}

static TEE_Result dec_random_key(uint32_t param_types,
	TEE_Param params[4])
{
	
	char* memref_buffer = (char*)params[0].memref.buffer;
	int length = strlen (params[0].memref.buffer);
	char encrypted [1000] = {0,};	
	
	memcpy(encrypted, memref_buffer, length);
	random_key = encrypted[length - 1];

	if('a' <= random_key && random_key <= 'z'){
		random_key -= 'a';
		random_key -= root_key;
		random_key += 26;
		random_key %= 26;
		random_key += 'a';
	}
	
	if ('A' <= random_key && random_key <= 'Z') {
		random_key -= 'A';
		random_key -= root_key;
		random_key += 26;
		random_key %= 26;
		random_key += 'A';
	}
	return TEE_SUCCESS;
}


static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	char* text = (char *)params[0].memref.buffer;
	int length = strlen (params[0].memref.buffer);
	char decrypted [1000] = {0,};
	
	memcpy(decrypted, text, length);

	for(int i = 0; i < length - 1; i++){
		if('a' <= decrypted[i] && decrypted[i] <= 'z'){
			decrypted[i] -= 'a';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] %= 26;
			decrypted[i] += 'a';
		}
		
		if ('A' <= decrypted[i] && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] %= 26;
			decrypted[i] += 'A';
		}
	}
	decrypted[length - 1] = '\0';
	memcpy(text, decrypted, length);

	return TEE_SUCCESS;
}



TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	
	ret = TEE_GetObjectInfo1(key, &key_info);

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);

	ret = TEE_SetOperationKey(*handle, key);

	return ret;
}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = 1000;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	
	DMSG("CREATE KEY PAIR\n");
	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	void *plain_text = params[0].memref.buffer;
	size_t plain_length = params[0].memref.size;
	void *cipher_text = params[1].memref.buffer;
	size_t cipher_length = params[1].memref.size;

	DMSG("ENCRYPT START");

	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);

	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_text, plain_length, cipher_text, cipher_length);					
	DMSG("\n********* Encryption Complete ***********\n");
	return ret;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return create_random_key(param_types, params);
	case TA_TEEencrypt_CMD_ENC_RANDOMKEY:
		return enc_random_key(param_types, params);	
	case TA_TEEencrypt_CMD_DEC_RANDOMKEY:
		return dec_random_key(param_types, params);

	case TA_TEEencrypt_CMD_RSA_ENCRYPT:
		return RSA_encrypt(sess_ctx, param_types, params);
	case TA_TEEencrypt_CMD_RSA_KEY_GET:
		return RSA_create_key_pair(sess_ctx);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
