 /*
 Attach a new syscall xcrypt to en/decrypt file                                                      
 Header file for both kernel and user space program

 Copyright (C) 2015 Beijie Li <beli@cs.stonybrook.edu>         
 */                                                            
                                                               
#ifndef XCRYPT_H                                               
#define XCRYPT_H                                                                                          
                                                              
#define ENCRYPT 1                                              
#define DECRYPT 0                                              
                                                              
#define DEFAULT_KEY_LEN 16                                     
#define DEFAULT_BLK_SIZE PAGE_SIZE                             
// #define EXTRA_CREDIT
                                                               
struct xcrypt_args {                                            
    char *key;
    int keylen;                                                                                             
    int flag;
    char *infile;                                              
    char *outfile;                                                                                                 
#ifdef EXTRA_CREDIT                                            
    int cipher_type;                                           
    int blk_size;                                              
#endif                                                         
};                                                             
                                                               
#ifdef EXTRA_CREDIT                                            
                                                               
#define MIN_BLK_SIZE 8                                         
#define MAX_BLK_SIZE PAGE_SIZE                                 
                                                               
static char *cipher_opt[] = {                                  
    "cbc(aes)",                                                
    "cbc(blowfish)",                                           
    "cbc(twofish)",                                            
    "cbc(anubis)",                                             
    /* have not found out how to make those three work         
    "cbc(des)",                                                
    "cbc(des3_ede)",                                           
    "cbc(camellia)"                                            
     */                                                        
};                                                             
#endif                                                         
                                                               
#endif                                                        












































