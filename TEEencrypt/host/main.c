/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{	
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0, };
	char ciphertext[64] = {0, };
	int len=64;
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	if(strcmp(argv[1], "-e") == 0){ //case encryption
		printf("Invoking TA to encrypt txt file'\n");
		char *Txt_File_name = argv[2]; //txt file name
		FILE* fp = fopen(Txt_File_name, "r");
		fread(plaintext, 1, len, fp); //read txt and save it to plaintext
		fclose(fp); //close file
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
		memcpy(ciphertext, op.params[0].tmpref.buffer, len); //get Encrypt string and key by TA
		printf("Encrypted Text : %s\n", ciphertext);
		printf("Encrypted Key : %d\n", op.params[1].value.a);
		FILE* fp_string_d = fopen("encrypted_string.txt", "w"); //save string as FILE
		fputs(ciphertext, fp_string_d);
		fclose(fp_string_d);
		FILE* fp_key = fopen("encrypted_key.txt", "w"); //save key as FILE
		char str_key[20];
		sprintf(str_key, "%d", op.params[1].value.a); //integer to string
		fputs(str_key, fp_key);
		fclose(fp_key);
	}
	else{ //case decryption
		printf("Invoking TA to decrypt txt file'\n");
		char *Encrypted_string_file = argv[2];
		char *Encrypted_key_file = argv[3];
		FILE* fp_string = fopen(Encrypted_string_file, "r");

		fread(plaintext, 1, len, fp_string); //read txt and save it to plaintext
		fclose(fp_string); //close file

		FILE* fp_key = fopen(Encrypted_key_file, "r");
		char tmp_st[64];
		fread(tmp_st, 1, len, fp_key);
		int encrypted_key = atoi(tmp_st); //string to int
		printf("encrypted_key : %d\n", encrypted_key);
		fclose(fp_key);
		
		op.params[1].value.a = encrypted_key;
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
		memcpy(ciphertext, op.params[0].tmpref.buffer, len); //get decrypted string
		printf("Decrypted text : %s\n", ciphertext);
		printf("Decrypted Key : %d\n", op.params[1].value.a);
		fp_string = fopen("decrypted_string.txt", "w"); //save string as FILE
		fputs(ciphertext, fp_string);
		fclose(fp_string);

		fp_key = fopen("decrypted_key.txt", "w"); //save key as FILE
		char str_key[20];
		sprintf(str_key, "%d", op.params[1].value.a); //integer to string
		fputs(str_key, fp_key);
		fclose(fp_key);
	}
	
	
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
