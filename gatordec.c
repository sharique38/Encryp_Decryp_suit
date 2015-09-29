/*
 ============================================================================
 Name        : gatordec.c
 Author      : Sharique
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <gcrypt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>

void decrypt(char *outfile, char *inpfile) {

	gcry_err_code_t err = 0;
	gcry_cipher_hd_t gchandle;
	const int blks = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	const int keyl = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	long outfileSize = 0;
	char key[keyl];
	const char* salt = "iuyjdbnbtaqonbgt";
	//open output file
	FILE *fout = fopen(outfile, "r");
	if (!fout) {
		printf("output file name : %s\n", outfile);
		fout = fopen(outfile, "w");
	} else {
		printf("Output file already exist on disk.\n");
		return;;
	}
	char password[100];
	do {
		printf("Please enter password between 8-20 chars :");
		scanf("%s", password);
	} while (strlen(password) > 20 || strlen(password) < 8);

	err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
			GCRY_MD_SHA256, salt, strlen(salt), 937, keyl, key);
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
				gcry_strerror(err));
		exit(EXIT_FAILURE);
	}

	char ctext[blks];
	char extractedIV[blks];
	FILE *finp = fopen(inpfile, "r");
	fseek(finp, 0, SEEK_SET);
	unsigned char extractedHMAC[keyl + 1];

	fread(extractedHMAC, 1, keyl, finp); //extract HMAC from received file
	extractedHMAC[keyl] = '\0';

	// Compare calculated HMAC with extracted HMAC ---> start
	long cipherSize = 0;
	fseek(finp, 0, SEEK_END);
	cipherSize = ftell(finp) - keyl;
	fseek(finp, keyl, SEEK_SET);
	unsigned char *hmacBuffer = malloc(cipherSize + 1);
	fread(hmacBuffer, 1, cipherSize, finp);
	gcry_md_hd_t hd;
	err = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
				gcry_strerror(err));
		fclose(finp);
		fclose(fout);
		exit(EXIT_FAILURE);
	}
	err = gcry_md_setkey(hd, key, keyl);
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
				gcry_strerror(err));
		fclose(finp);
		fclose(fout);
		exit(EXIT_FAILURE);
	}
	err = gcry_md_enable(hd, GCRY_MD_SHA256);
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
				gcry_strerror(err));
		fclose(finp);
		fclose(fout);
		exit(EXIT_FAILURE);
	}
	gcry_md_write(hd, hmacBuffer, cipherSize);

	char thmac[keyl];
	unsigned char *hmac = thmac;
	hmac = gcry_md_read(hd, GCRY_MD_SHA256);

	int i = 0;
	int hflag = 1;
	for (; i < keyl; i++) {
		if (hmac[i] != extractedHMAC[i])
			hflag = 0;
	}
	if (hflag)
		printf("HMAC successfully matched\n");
	else
		printf("HMAC not matched\n");

	fseek(finp, keyl, SEEK_SET);
	// Compare calculated HMAC with extracted HMAC ---> end

	//Decryption algo ------> start
	fread(extractedIV, 1, blks, finp); // read IV
	err = gcry_cipher_open(&gchandle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,
			0);
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
				gcry_strerror(err));
		exit(EXIT_FAILURE);
	}

	err = gcry_cipher_setkey(gchandle, key, keyl);
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
				gcry_strerror(err));
		exit(EXIT_FAILURE);
	}
	err = gcry_cipher_setiv(gchandle, extractedIV, blks);
	if (err) {
		fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
				gcry_strerror(err));
		exit(EXIT_FAILURE);
	}

	if (!finp) {
		printf("Could not open input text file\n");
	} else {
		int x = 0;
		char plaintext[blks];
		while ((x = fread(plaintext, 1, blks, finp))) {
			if (x < blks) // add padding to last block
				outfileSize += x;
			err = gcry_cipher_decrypt(gchandle, ctext, blks, plaintext, x);
			if (err && x == blks) {
				fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
						gcry_strerror(err));
				fclose(finp);
				fclose(fout);
				exit(EXIT_FAILURE);
			}
			fwrite(ctext, 1, blks, fout);
		}
		gcry_cipher_close(gchandle);

		gcry_md_close(hd);

		fclose(finp);
		fclose(fout);
	}
	free(hmacBuffer);
	//Decryption algo ------> end
}

int main(int argc, char *argv[]) {

	int port = 5432;
	char outfile[100];
	int lflag = 0;
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, "l")) != -1)
		switch (c) {
		case 'l':
			lflag = 1;
			strcpy(outfile, argv[optind]);
			outfile[strlen(outfile) - 3] = '\0';
			break;
		case '?':
			if (isprint (optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
			exit(EXIT_FAILURE);
		}
	if (lflag) { // file based scenario
		decrypt(outfile, argv[optind]);
	} else { // Daemon mode case start
		if (argc > 1)
			port = atoi(argv[optind]);

		int server_socket;
		int peer_socket;
		char buffer[BUFSIZ];
		socklen_t sock_len;
		struct sockaddr_in server_addr;
		struct sockaddr_in peer_addr;
		long long file_size;
		char file_name[256] = "EncryptedFile.uf";
		long long remain_data;
		FILE *rcfp;

		/* Create server socket */
		server_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (server_socket == -1) {
			fprintf(stderr, "Error creating socket --> %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* Zeroing server_addr struct */
		memset(&server_addr, 0, sizeof(server_addr));
		/* Construct server_addr struct */
		server_addr.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr));
		server_addr.sin_port = htons(port);

		/* Bind */
		if ((bind(server_socket, (struct sockaddr *) &server_addr,
				sizeof(struct sockaddr))) == -1) {
			fprintf(stderr, "Error on bind --> %s", strerror(errno));

			exit(EXIT_FAILURE);
		}

		/* Listening to incoming connections */
		if ((listen(server_socket, 5)) == -1) {
			fprintf(stderr, "Error on listen --> %s", strerror(errno));

			exit(EXIT_FAILURE);
		}
		printf("Decryptor daemon listening on 127.0.0.1:%d\n", port);

		while (1) {
			/* Accepting incoming peers */
			peer_socket = accept(server_socket, (struct sockaddr *) &peer_addr,
					&sock_len);
			if (peer_socket == -1) {
				fprintf(stderr, "Error on accept --> %s", strerror(errno));

				exit(EXIT_FAILURE);
			}
			fprintf(stdout, "Accept peer --> %s\n",
					inet_ntoa(peer_addr.sin_addr));

			/* Receiving file size */
			recv(peer_socket, buffer, 256, 0);
			file_size = atoi(buffer);
			fprintf(stdout, "\nFile size : %d\n", file_size);

			/* Receiving file name */
			int length = recv(peer_socket, buffer, 256, 0);
			strncpy(file_name, buffer, 256);
			fprintf(stdout, "Received filename: %s\n", file_name);

			rcfp = fopen(file_name, "w");
			if (rcfp == NULL) {
				fprintf(stderr, "Failed to open file foo --> %s\n",
						strerror(errno));

				exit(EXIT_FAILURE);
			}

			remain_data = file_size;
			int len = 0;
			while (((len = recv(peer_socket, buffer, BUFSIZ, 0)) > 0)
					&& (remain_data > 0)) {
				fwrite(buffer, sizeof(char), len, rcfp);
				remain_data -= len;
				fprintf(stdout, "Receive %d bytes and we hope :- %d bytes\n",
						len, remain_data);
			}
			fclose(rcfp);

			strcpy(outfile, file_name);
			outfile[strlen(outfile) - 3] = '\0';
			decrypt(outfile, file_name); // run decryption algorithm
			printf("Decryption done, listening for next client\n");
		}

		close(peer_socket);
		close(server_socket);

	} // Daemon case end

	return EXIT_SUCCESS;
}
