/*
  Attach a new syscall xcrypt to en/decrypt file                                                      
  User-land program to generate excutable: pre-check input parameters, call sys_xcrypt
  Return 0 

  Copyright (C) 2015 Beijie Li <beli@cs.stonybrook.edu>         
 */   



/*
- flag: -e to encrypt; -d to decrypt
- flag: -c ARG to specify the type of cipher (as a string name)
  [Note: this flag is mainly for the extra credit part]
- flag: -p ARG to specify the encryption/decryption key
- flag: -h to provide a helpful usage message
- input file name
- output file name

User-level passwords should be at least 6 characters long.  Nevertheless, you
should not just pass the password into the kernel as is: it is too short.
You need to ensure that you pass a correctly sized encryption key into the
kernel.
*/


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h>

#include "xcrypt.h"

void display_usage()
{
	printf("Usage: xcipher [ OPTIONS ] SOURCE DESTINATION\n");
	printf("Encrypt/Decrypt SOURCE to DESTINATION using the specified passphrase \n");
#ifdef EXTRA_CREDIT
	printf("xcipher {-e|-d} [-c Cipher Type] [-l Key Length] [-u Block Size]\n"); 
	printf("        -p <PASSWORD> [-h] SOURCE DESTINATION\n");
#else
	printf("xcipher {-e|-d} -p <PASSWORD> [-h] SOURCE DESTINATION\n");
#endif

	printf(" -p:  to specify the password;\n");
	printf(" -h:  to display this message;\n");

	printf("\nMandatory arguments:\n");
	printf(" -e  to encrypt source to destination\n");
	printf(" -d  to decrypt source to destination\n");
	printf(" -p  to pecify the <PASSWORD>\n");
	printf(" SOURCE:  input file name;\n");
	printf(" DESTINATION: output file name;\n");
	printf("\nOptional arguments:\n");
#ifdef EXTRA_CREDIT
	printf(" -c  to specify the Cipher Type, AES is default method;\n");
	printf(" -u  to specify the size of block for I/O default: PAGE_SIZE;\n");
	printf(" -l  to specify the length of cipher key passing into kernel;\n");
	printf("     if specify in encryption process, specify that in decryption;\n");
	printf("	 range [64, 448], default: 128;\n");
#endif
	printf(" -h  to display this message.\n");
}


/* For User space file checking, I take use some functions from Blowfish Cipher Tool.
 Credeits to Author: Cody Moore. Source code: https://github.com/dotCipher/blowfish-tool
 I import fileEXists, isDirectory, isRegularFile and isSameFils to validate files in
 user space.
*/

/* Handles checking if file exists
 * as well as proper permissions on file
 * SUCCESS CODE(S):
 * 0 = Success (File DOES NOT exist)
 * ERROR CODE(S):
 * 1 = File does exist
 * 2 = File does exist & no permissions
 */
int fileExists(char *fName){
  struct stat buf;
  errno=0;
  int chk = stat(fName, &buf);
  if(errno!=0){
  	return (chk==0);
	} else {
		return 2;
	}
}

/* Handles checking if path is directory
 * SUCCESS CODE(S):
 * 0 = Success (Path is NOT a directory)
 * ERROR CODE(S):
 * 1 = Path is a directory
 * 2 = Out of memory
 */
int isDirectory(char *path){
  struct stat *buf;
  buf = (struct stat*)malloc(sizeof(struct stat));
  if(buf==NULL){
  	free(buf);
  	return 2;
  }
  stat(path,buf);
  if(buf->st_mode & S_IFDIR){
  	free(buf);
    return 0;
  } else {
  	free(buf);
    return 1;
  }
}

/* Handles checking if the given path of a file
 * is pointing to a regular file.
 * (NOTE: If path is a symlink
 * follow it to find a regular file.)
 * SUCCESS CODE(S):
 * 0 = Success (Path points to regular file)
 * ERROR CODE(S):
 * 1 = Path is a character device
 * 2 = Path is a block device
 * 3 = Path is a named pipe
 * 4 = Path is a socket
 * 5 = Path is a directory
 * 6 = Path is a symlink
 */
int isRegularFile(char *path){
	struct stat *buf;
	buf = (struct stat*)malloc(sizeof(struct stat));
	stat(path,buf);
	if(buf->st_mode & S_IFREG){
		free(buf);
		return 0;
	} else if(buf->st_mode & S_IFCHR){
		free(buf);
		return 1;
	} else if(buf->st_mode & S_IFBLK){
		free(buf);
		return 2;
	} else if(buf->st_mode & S_IFIFO){
		free(buf);
		return 3;
	} else if(buf->st_mode & S_IFSOCK){
		free(buf);
		return 4;
	} else if(buf->st_mode & S_IFDIR){
		free(buf);
		return 5;
	} else{
		free(buf);
		return 6;
	}
}

/* Handles checking if two files are the same.
 * This method assumes the files exist.
 * (checks for symlinks and hardlinks)
 * SUCCESS CODE(S):
 * 0 = Success (NOT the same file) 
 * ERROR CODE(S):
 * 1 = Paths are the same (same referencing)
 * 2 = Hardlinks to same file
 * 3 = In/Out symlinks point to same file
 * 4 = Input symlink points to outfile
 * 5 = Output symlink points to infile
 */
int isSameFiles(char *in_path, char *out_path){
	struct stat *in_buffer;
	struct stat *out_buffer;
	in_buffer = (struct stat*)malloc(sizeof(struct stat));
	out_buffer = (struct stat*)malloc(sizeof(struct stat));
	stat(in_path,in_buffer);
	stat(out_path,out_buffer);
	// Checks if the basic paths are the same
	if(strcmp(in_path,out_path)==0){
		free(in_buffer); free(out_buffer);
		return 1;
	} else {
		// Check if either are symlinks
		lstat(in_path,in_buffer);
		lstat(out_path,out_buffer);
		if(!(in_buffer->st_mode & S_IFLNK) 
		&& !(out_buffer->st_mode & S_IFLNK)){
			// If both are not links then check to be SURE they are same file
			//  (Aka Hardlinks to same file)
			if((in_buffer->st_dev==out_buffer->st_dev) 
			&& (in_buffer->st_ino==out_buffer->st_ino)){
				free(in_buffer); free(out_buffer);
				return 2;
			} else {
				// They must be pointing to two different files
				// (Not Hardlinks)
				free(in_buffer); free(out_buffer);
				return 0;
			}
		} else if((in_buffer->st_mode & S_IFLNK) 
		&& (out_buffer->st_mode & S_IFLNK)){
			// Both input file & output file are symlinks
			// Check if they point to the same file
			stat(in_path,in_buffer);
			stat(out_path,out_buffer);
			if((in_buffer->st_dev==out_buffer->st_dev) 
			&& (in_buffer->st_ino==out_buffer->st_ino)){
				free(in_buffer); free(out_buffer);
				return 3;
			} else {
				free(in_buffer); free(out_buffer);
				return 0;
			}
		} else if((in_buffer->st_mode & S_IFLNK) 
		&& !(out_buffer->st_mode & S_IFLNK)){
			// Only the input file is a symlink
			// Check if input points to output
			stat(in_path,in_buffer);
			stat(out_path,in_buffer);
			if((in_buffer->st_dev==out_buffer->st_dev) 
			&& (in_buffer->st_ino==out_buffer->st_ino)){
				free(in_buffer); free(out_buffer);
				return 4;
			} else {
				free(in_buffer); free(out_buffer);
				return 0;
			}
		} else {
			// Only the output file is a symlink
			// Check if output points to input
			stat(in_path,in_buffer);
			stat(out_path,out_buffer);
			if((in_buffer->st_dev==out_buffer->st_dev) 
			&& (in_buffer->st_ino==out_buffer->st_ino)){
				free(in_buffer); free(out_buffer);
				return 5;
			} else {
				free(in_buffer); free(out_buffer);
				return 0;
			}
		}
	}
}

/* Chop '\n' in password by traversing string
 * Credits to Junxing Yang, https://github.com/piekill/os_homework1.
 * I changed the function name and parameters.
 */
void chop(char **des, const char *src)
{
	char *temp = (char *)malloc(strlen(src)+1);
	int i,j;  
	for (i = 0, j = 0; src[i] != '\0'; i++)  
	{  
		if (src[i] != '\n')  
			temp[j++] = src[i];  
        }
    	temp[j] = '\0';
	*des = (char *)malloc(strlen(temp)+1);
	strcpy(*des, temp);
	free(temp);
}

typedef struct options_struct{
	int  encryptFlag, decryptFlag, pwdFlag;
	char *pwd, *inputFile, *outputFile;
} options;


/* This function uses getopt() and parses the given options
 * it fills up the options structure which is then used to 
 * invoke the system call. It checks input output file as well.
 */
int parse_options(options *args_vec, int argc, char **argv)
{
	int opt = 0;
	int errFlag = 0;

#ifdef EXTRA_CREDIT
	char *optStr = "p:c:l:u:edh"
#else
	char *optStr = "edp:h"; 
#endif

	int args_num = 6;
	if (argc < args_num) {
		puts("wrong argument(s): too few arguments");
		display_usage();
		return -1;
	}
	while ( -1 != (opt = getopt(argc, argv, optStr)) )
	{
		switch (opt) {
		case 'e':
			args_vec->encryptFlag = 1;
			break;
		case 'd':
			args_vec->decryptFlag = 1;
			break;
		case 'p':
			/* remove the '\n' from password */
			args_vec->pwdFlag = 1;
			chop(&args_vec->pwd, optarg);
			break;
		case 'h':
			display_usage();
			break;
		case '?':
			display_usage();
			return 0;
		default:
			errFlag = 1;
			break;
		}
	}
	if (args_vec->encryptFlag == args_vec->decryptFlag) {
		printf("wrong argument(s): must specify encrypt or decrypt\n");
		display_usage();
		return -1;
	}
	else if (1 == errFlag) {
		printf("wrong argument(s)\n");
		display_usage();
		return -1;
	}
	else if (0 == args_vec->pwdFlag) {
		printf("0 == args_vec->pwdFlag");
		printf("wrong argument(s): null key\n");
		display_usage();
		return -1;
	}
	else if (strlen(args_vec->pwd)<6){
		printf("wrong argument(s): password should be at least 6 char long\n");
		display_usage();
		return -1;
	}
	else if (optind + 2 != argc) {
		printf("wrong argument(s): null SOURCE/DESTINATION file\n");
		display_usage();
		return -1;
	}

	else{
		args_vec->inputFile = argv[optind];
		args_vec->outputFile = argv[optind + 1];
	}

	if (args_vec->pwd == NULL) {
		printf("args_vec->pwd == NULL");
		printf("wrong argument(s): null key\n");
		return -1;
	}
	if(args_vec->inputFile == NULL){
		puts("wrong argument(s): null infile");
		return -1;
	}
	if(args_vec->outputFile == NULL){
		puts("wrong argument(s): null outfile");
		return -1;
	}
	char *infile_name = args_vec->inputFile;
	char *outfile_name = args_vec->outputFile;
	// ----- <infile> Error Checking -----  
	int i;
	if(1){
    	i=fileExists(infile_name);
      	if(i==0){
        // <infile> DOES NOT exist
        	fprintf(stderr,"Error Code 5: <infile> does not exist\n");
        	free(infile_name); free(outfile_name);
        	exit(5);
      	} else if(i==2){
      	// <infile> DOES exist
      	// Is it a directory?
      		if((isDirectory(infile_name))!=1){
      		// <infile> DOES exist AND is a directory
        		fprintf(stderr,"Error Code 6: <infile> is a directory\n");
        		free(infile_name); free(outfile_name);
      	  		exit(6);
      		}
      	} else {
      	// <infile> DOES exist AND is NOT a directory
      }
    }
    // Postconditions:
    // <infile> DOES exist and IS NOT a directory
    // OR <infile> is set to STDIN
    // with no i/o or permission errors
    
    // ----- <outfile> Error Checking -----
    if(1){
    	if((fileExists(outfile_name))!=1){
    		// <outfile> DOES NOT exist
    		// do nothing - possible error caught
    		// when calling open later on.
    	} else if((isDirectory(outfile_name))!=1){
    		// <outfile> DOES exist AND is directory
    		fprintf(stderr,"Error Code 6: <outfile> is a directory\n");
    		free(infile_name); free(outfile_name);
    		exit(6);
    	} else {
    		// <outfile> DOES exist AND is NOT a directory
    		fprintf(stderr, "Warning: <outfile> exists, overwritting...\n");
    	}
    }
    // Postconditions:
    // <outfile> IS NOT a directory AND exists (either made or overwrote)
    // OR <outfile> is set to STDOUT
    int sf_code;
    if(1){
    	// Check if infile and outfile are the same
    	sf_code = isSameFiles(infile_name, outfile_name);
    	if(sf_code==1){
    		// Paths are the same references
    		fprintf(stderr,"Error Code 7: <infile> and <outfile> are the same path\n");
    		free(infile_name); free(outfile_name);
    		exit(7);
    	} else if(sf_code==2){
    		// Hardlinks to same file
    		fprintf(stderr,"Error Code 7: <infile> and <outfile> are hardlinks to same file\n");
    		free(infile_name); free(outfile_name);
    		exit(7);
   	 } else if(sf_code==3){
 	   		// In/Out symlinks point to same file
 	   		fprintf(stderr,"Error Code 7: <infile> and <outfile> are symlinks to same file\n");
    		free(infile_name); free(outfile_name);
    		exit(7);
    	} else if(sf_code==4){
    		// Input symlink points to outfile
    		fprintf(stderr,"Error Code 7: <infile> symlink points to <outfile>\n");
    		free(infile_name); free(outfile_name);
    		exit(7);
    	} else if(sf_code==5){
    		// Output symlink points to infile
    		fprintf(stderr,"Error Code 7: <outfile> symlink points to <infile>\n");
    		free(infile_name); free(outfile_name);
  	  	exit(7);
  	  } else{
  	  	// No error, continue on
 	  	}
    }
    
    // Check if <infile> or <outfile> is a char/block special device
    if(1){
   		switch(isRegularFile(infile_name)){
    		case 0:
    			// Regular File
    			break;
    		case 1:
    			// Character Device
    			fprintf(stderr,"Error Code 7: <infile> is a character device\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 2:
    			// Block Device
    			fprintf(stderr,"Error Code 7: <infile> is a block device\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 3:
    			// FIFO - Named Pipe
    			fprintf(stderr,"Error Code 7: <infile> is a named pipe\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 4:
    			// Socket
    			fprintf(stderr,"Error Code 7: <infile> is a socket\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 5:
    			// Directory
    			fprintf(stderr,"Error Code 7: <infile> is a directory\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    	}
    }
    if(1){
    	switch(isRegularFile(outfile_name)){
    		case 0:
    			// Regular File
    			break;
    		case 1:
    			// Character Device
    			fprintf(stderr,"Error Code 7: <outfile> is a character device\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 2:
    			// Block Device
    			fprintf(stderr,"Error Code 7: <outfile> is a block device\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 3:
    			// FIFO - Named Pipe
    			fprintf(stderr,"Error Code 7: <outfile> is a named pipe\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 4:
    			// Socket
    			fprintf(stderr,"Error Code 7: <outfile> is a socket\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    		case 5:
    			// Directory
    			fprintf(stderr,"Error Code 7: <infile> is a directory\n");
    			free(infile_name); free(outfile_name);
    			exit(7);
    	}
    }
	return 0;
}



int main(int argc, char *argv[])
{	
	
	/*Initialize xcrypt_args */
	options opts;
	struct xcrypt_args xcryptArgs;
	unsigned char password[MD5_DIGEST_LENGTH];
	int validInput = -1;
	char ch;
	char mdString[33];
	int i;
	char key[DEFAULT_KEY_LEN + 1];
	memset(&xcryptArgs, 0, sizeof xcryptArgs);
	memset(&opts, 0, sizeof opts);

	/*Call parse options to take input from shell*/
	validInput = parse_options(&opts,argc,argv);

	if (validInput != 0){
		printf("Invalid input parameter(s), use 'xcipher -h' to check usage.\n");
		return -1;
	}
       	
    /* Compute the one-way hash of the user specified password 
     * to generate the key
     * Using MD5 function in openssl
     * Credits: http://www.askyb.com/cpp/openssl-md5-hashing-example-in-cpp/
     * */
	MD5((const unsigned char *)opts.pwd, strlen(opts.pwd), password);
    	for (i = 0; i < 16; i++)
        	sprintf(&mdString[i*2], "%02x", (unsigned int)password[i]);
	
	for (i = 0; i < 16; i++){
		key[i] = mdString[i];
	}
	key[i] = '\0';
	/* fill the structure to be passed to the kernel */
	xcryptArgs.key = key;
	//const char *temp = (const char*)password;
	
	//printf("TESTING: after convert to char psw length %d\n", strlen(temp));
	//printf("%d\n", strcmp(xcryptArgs.key, temp));
	xcryptArgs.keylen = strlen(xcryptArgs.key); 
	xcryptArgs.flag = (opts.encryptFlag == 1) ? ENCRYPT : DECRYPT;
	xcryptArgs.infile = opts.inputFile;
	xcryptArgs.outfile = opts.outputFile;
	/*
	printf("key is %s\n", xcryptArgs.key);
	printf("key length is %d\n", xcryptArgs.keylen);
	printf("key length is strlen %d\n", strlen(xcryptArgs.key));
	printf("E/D flag is %d\n", xcryptArgs.flag);
	printf("infile is %s\n", xcryptArgs.infile);
	printf("outfile is %s\n", xcryptArgs.outfile);
	*/
	if (access(xcryptArgs.infile, F_OK) != 0) {
		printf("No such file \"%s\"\n", xcryptArgs.infile);
		return -1;
	}
	else
		printf("Input file exists, opening...\n");

	if (access(xcryptArgs.outfile, F_OK) == 0) {
		printf("Overwrite existing file \"%s\"? (y or n) ", xcryptArgs.outfile);
		ch = getchar();
		if (tolower(ch) != 'y') {
			return 0;
		}
	}
	else
		printf("Output file not exists, creating...\n");
	if(syscall(__NR_xcrypt, &xcryptArgs) != 0) {
		perror("xcrypt");
	}
	else{
		printf("syscall xcrypt succeeded!\n");
	}
	return 0;

}
