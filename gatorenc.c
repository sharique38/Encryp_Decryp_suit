/*
 ============================================================================
 Name        : NetSec.c
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

int main(int argc, char *argv[]) {

	int lflag = 0;
	int dflag = 0;
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, "dl")) != -1)
		switch (c) {
		case 'd':
			dflag = 1;
			break;
		case 'l':
			lflag = 1;
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

	if (dflag || lflag) {
		gcry_err_code_t err = 0;
		gcry_cipher_hd_t gchandle;
		const int blks = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
		const int keyl = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
		long outfileSize = 0;
		char key[keyl];
		const char* salt = "iuyjdbnbtaqonbgt";
		//open output file
		char outfile[256];
		strcpy(outfile, argv[optind]);
		strncat(outfile, ".uf\0", 4);
		FILE *fout = fopen(outfile, "r");
		if (!fout) {
			//printf("output file name : %s\n", outfile);
			fout = fopen(outfile, "w");
		} else {
			printf("Output file already exist on disk.\n");
			exit(EXIT_FAILURE);
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
		char *iv = "1234567890123456";
		fwrite(iv, 1, blks, fout);
		outfileSize += blks;

		// Encryption Algo ----> start
		err = gcry_cipher_open(&gchandle, GCRY_CIPHER_AES256,
				GCRY_CIPHER_MODE_CBC, 0);
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
		err = gcry_cipher_setiv(gchandle, iv, blks);
		if (err) {
			fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
					gcry_strerror(err));
			exit(EXIT_FAILURE);
		}
		FILE *finp = fopen(argv[optind], "r");
		if (!finp) {
			printf("Could not open text file\n");
		} else {
			int x = 0;
			char plaintext[blks];
			while ((x = fread(plaintext, 1, blks, finp))) {
				if (x < blks) { // add padding to last block
					fseek(finp, 0, SEEK_END);
					for (; x < blks; x++) {
						plaintext[x] = '$';
						fputc('$', finp);
					}
				}

				err = gcry_cipher_encrypt(gchandle, ctext, blks, plaintext, x);
				if (err && x == blks) {
					fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
							gcry_strerror(err));
					fclose(finp);
					fclose(fout);
					exit(EXIT_FAILURE);
				}
				fwrite(ctext, 1, blks, fout);
				outfileSize += blks;
			}
			gcry_cipher_close(gchandle);
			fclose(fout);
			//generating HMAC
			fout = fopen(outfile, "r+");
			fseek(fout, 0, SEEK_SET);
			unsigned char *hmacBuffer = malloc(outfileSize + 1);
			fread(hmacBuffer, 1, outfileSize, fout);
			fseek(fout, 0, SEEK_END);
			fclose(fout);
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
			gcry_md_write(hd, hmacBuffer, outfileSize);
			char thmac[keyl];
			unsigned char *hmac = thmac;
			hmac = gcry_md_read(hd, GCRY_MD_SHA256);
			//printf("%s\n",hmac);
			//writing file contents as hmac(32 byte) + iv(16 byte) + cipher
			fout = fopen(outfile, "w");
			fwrite(hmac, 1, keyl, fout);
			fwrite(hmacBuffer, 1, outfileSize, fout);
			gcry_md_close(hd);
			fclose(finp);
			fclose(fout);
			free(hmacBuffer);
			// Encryption Algo ----> end
		}

		/* Transferring file over ip */
		if (dflag) {
			int client_socket;
			ssize_t len;
			struct sockaddr_in server_addr;
			int fd;
			int sent_bytes = 0;
			char file_size[256];
			struct stat file_stat;
			int offset;
			int remain_data;
			char ip[15], port[4];

			int i = 0, j = 0;
			for (; argv[optind + 1][i] != ':'; i++) {
				ip[i] = argv[optind + 1][i];
			}
			i++;
			for (; i < strlen(argv[optind + 1]); i++, j++) {
				port[j] = argv[optind + 1][i];
			}

			/* Create client socket */
			client_socket = socket(AF_INET, SOCK_STREAM, 0);
			if (client_socket == -1) {
				fprintf(stderr, "Error creating socket --> %s",
						strerror(errno));

				exit(EXIT_FAILURE);
			}

			/* Zeroing server_addr struct */
			memset(&server_addr, 0, sizeof(server_addr));
			/* Construct server_addr struct */
			server_addr.sin_family = AF_INET;
			inet_pton(AF_INET, ip, &(server_addr.sin_addr));
			server_addr.sin_port = htons(atoi(port));

			/* Connect to the server */
			if (connect(client_socket, (struct sockaddr *) &server_addr,
					sizeof(struct sockaddr)) == -1) {
				fprintf(stderr, "Error on connect --> %s\n", strerror(errno));

				exit(EXIT_FAILURE);
			}
			fd = open(outfile, O_RDONLY);
			if (fd == -1) {
				fprintf(stderr, "Error opening file --> %s", strerror(errno));

				exit(EXIT_FAILURE);
			}

			/* Get file stats */
			if (fstat(fd, &file_stat) < 0) {
				fprintf(stderr, "Error fstat --> %s", strerror(errno));

				exit(EXIT_FAILURE);
			}

			fprintf(stdout, "File Size: \n%ld bytes\n", file_stat.st_size);

			sprintf(file_size, "%d", file_stat.st_size);

			/* Sending file size */
			len = send(client_socket, file_size, sizeof(file_size), 0);
			if (len < 0) {
				fprintf(stderr, "Error on sending greetings --> %s",
						strerror(errno));

				exit(EXIT_FAILURE);
			}
			fprintf(stdout, "Client sent %ld bytes for the size\n", len);
			/* Sending file name */
			len = send(client_socket, outfile, sizeof(outfile), 0);
			if (len < 0) {
				fprintf(stderr, "Error on sending greetings --> %s",
						strerror(errno));

				exit(EXIT_FAILURE);
			}
			fprintf(stdout, "Client sent %ld bytes for the filename: %s\n", len,
					outfile);
			offset = 0;
			remain_data = file_stat.st_size;
			/* Sending file data */
			while (((sent_bytes = sendfile(client_socket, fd, &offset, BUFSIZ))
					> 0) && (remain_data > 0)) {
				fprintf(stdout,
						"1. Client sent %d bytes from file's data, offset is now : %d and remaining data = %d\n",
						sent_bytes, offset, remain_data);
				remain_data -= sent_bytes;
				fprintf(stdout,
						"2. Client sent %d bytes from file's data, offset is now : %d and remaining data = %d\n",
						sent_bytes, offset, remain_data);
			}
			close(client_socket);

		}
	}
	return EXIT_SUCCESS;
}
