#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/md5.h>
#include <linux/scatterlist.h>
#include <linux/moduleloader.h>

#include "xcrypt.h"

#define PAD_SIZE 16
#define FILE_PATH_MAX 254
#define AES_BLOCK_SIZE 16

#define IV "xcryptabcdefghig"

const u8 *aes_iv = (u8 *) IV;

extern asmlinkage long (*sysptr) (void *args);

/*
 * File consists of source-code copied from CEPH File System source in
 * net/ceph/crypto.c I have copied functions ceph_aes_encrypt() and
 * ceph_aes_decrypt() functions from the file and made some modifications.
 */
int aes_encrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
	struct scatterlist sg_in[2], sg_out[1];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)",
							      0,
							      CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	int ret;
	void *iv;
	int ivsize;
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	char pad[AES_BLOCK_SIZE];

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	memset(pad, zero_padding, zero_padding);
        
	*dst_len = src_len + zero_padding;

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst, *dst_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	
	memcpy(iv, aes_iv, ivsize);
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
				       src_len + zero_padding);
	crypto_free_blkcipher(tfm);
	if (ret < 0){
		 /* 
		 printk(KERN_ALERT "aes_crypt failed %d\n", ret); 
		 */
		return ret;
	}
	/*
	print_hex_dump(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			dst, *dst_len, 1);
        */
        return 0;
}

/*
 * The source-code of this function is copied from CEPH File System source
 * in linux/net/ceph/crypto.c I have renamed it to aes_decrypt() and did some
 * modifications.
 */ 
int aes_decrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
	struct scatterlist sg_in[1], sg_out[2];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 
							      0,
							      CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm };
	char pad[AES_BLOCK_SIZE];
	void *iv;
	int ivsize;
	int ret;
	int last_byte;

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 2);
	sg_set_buf(sg_in, src, src_len);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);

	memcpy(iv, aes_iv, ivsize);


	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
	crypto_free_blkcipher(tfm);
	if (ret < 0) {
		return ret;
	}

	if (src_len <= *dst_len)
		last_byte = ((char *)dst)[src_len - 1];
	else
		last_byte = pad[src_len - *dst_len - 1];
	if (last_byte <= AES_BLOCK_SIZE && src_len >= last_byte) 
		*dst_len = src_len - last_byte;
	/*
	} else {
		
		printk(KERN_ALERT 
			"aes_decrypt got bad padding %d on src len %d\n", 
			last_byte, 
			(int)src_len);
		return -EPERM;  // bad padding 
	}
	*/

	/*
	print_hex_dump(KERN_ERR, "dec out: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			dst, *dst_len, 1);
	*/

	return 0;
}

/* check arguments passing into kernel before copying */
int check_args(void *args)
{
	struct xcrypt_args *ptr = (struct xcrypt_args *) args;

	if (ptr == NULL)
		goto out_efault;
	if (unlikely(!access_ok(VERIFY_READ, ptr, sizeof(struct xcrypt_args))))
		goto out_efault;
	if ((ptr->flag != 1) && (ptr->flag != 0)){
		goto out_einval;
	}
	/* check if the pointer to the key buffer is accessible */
	if (ptr->key == NULL)
	 	goto out_efault;
	if (unlikely(!access_ok(VERIFY_READ, ptr->key, ptr->keylen)))
		goto out_efault;
	/* check if the pointer to input file name is accesible */
	if (ptr->infile == NULL)
		goto out_efault;
	if (unlikely(!access_ok(VERIFY_READ, 
	    			ptr->infile, sizeof(ptr->infile))))
		goto out_efault;
	/* check if the pointer to the output file name is accessible */
	if (ptr->outfile == NULL)
		goto out_efault; 
	if (unlikely(!access_ok(VERIFY_READ, 
	    			ptr->outfile, sizeof(ptr->outfile))))
		goto out_efault;
	/* check if file name is too long */
	if ((strlen(ptr->infile) > FILE_PATH_MAX) || 
	    (strlen(ptr->outfile) > FILE_PATH_MAX))
		goto out_enametooling;
	/* check if keybuf is within KEYBUF_MIN and KEYBUF_MAX */
	if ((strlen(ptr->key)) != DEFAULT_KEY_LEN)
		goto out_emsgsize;
	goto out;
	
out_einval:
	return -EINVAL;
out_efault:
	return -EFAULT;
out_enametooling:
	return -ENAMETOOLONG;
out_emsgsize:
	return -EMSGSIZE;
out:
	return 0;
}


static int set_xcrypt_args(struct xcrypt_args *kptr, const struct xcrypt_args *ptr)
{
	int err = 0;
	kptr->key = kzalloc(strlen(ptr->key), GFP_KERNEL);
	if (kptr->key == NULL) {
		err = -ENOMEM;
		goto out;
	}
	err = copy_from_user(kptr->key, ptr->key, strlen(ptr->key));
	if (err)
		goto out_key;
	// printk("kptr->key %s\n", kptr->key);
	// printk("ptr->key %s\n", ptr->key);
	// printk("TESTING key copy: %d\n", strcmp(kptr->key, ptr->key));

	kptr->infile = kzalloc(strlen(ptr->infile), GFP_KERNEL);
	if (kptr->infile == NULL) {
		err = -ENOMEM;
		goto out_key;
	}
	err = copy_from_user(kptr->infile, ptr->infile, strlen(ptr->infile));
	if (err)
		goto out_infile;
	// printk("TESTING infile copy: %d\n", strcmp(kptr->infile, ptr->infile)); 

	kptr->outfile = kzalloc(strlen(ptr->outfile), GFP_KERNEL);
	if (kptr->outfile == NULL) {
		err = -ENOMEM;
		goto out_infile;
	}
	err = copy_from_user(kptr->outfile, ptr->outfile, strlen(ptr->outfile));
	if (err)
		goto out_outfile;
	// printk("TESTING outfile copy: %d\n", strcmp(kptr->outfile, ptr->outfile)); 
          
	kptr->flag = ptr->flag;
	kptr->keylen = ptr->keylen;
	goto out;

out_outfile:
	kfree(kptr->outfile);
out_infile:
	kfree(kptr->infile);
out_key:
	kfree(kptr->key);
out:
	return err;
}

/*
 * Read "len" bytes from "filename" into "buf".
 * "buf" is in kernel space.
 */

int wrapfs_read_file(const char *filename, void *buf, int len)
{
    struct file *filp;
    mm_segment_t oldfs;
    int bytes;
    /* Chroot? Maybe NULL isn't right here */
    filp = filp_open(filename, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
	printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
	return -1;  /* or do something else */
    }

    if (!filp->f_op->read)
	return -2;  /* file(system) doesn't allow reads, file_operation poiter is NULL */

    /* now read len bytes from offset 0 */
    filp->f_pos = 0;		/* start offset */
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    bytes = filp->f_op->read(filp, buf, len, &filp->f_pos);
    set_fs(oldfs);

    /* close the file */
    filp_close(filp, NULL);

    return bytes;
}


static int make_preamble(const struct xcrypt_args *kptr, char *preamble)
{
	int ret = 0;
	memcpy(preamble, kptr->key, DEFAULT_KEY_LEN);
	if (strlen(preamble) != DEFAULT_KEY_LEN){
		ret = -EINVAL;
		printk("create preamble failed!\n");
	}
	return ret;
}

static int write_preamble(struct file *outfilp, const char *preamble, int len)
{
	return outfilp->f_op->write(outfilp, (void *)preamble,
				len, &outfilp->f_pos);
}

static int check_preamble(struct file *infilp, char *preamble)
{
	int ret = 0;
	char *strInPreamble = NULL;
	strInPreamble = kzalloc(DEFAULT_KEY_LEN, GFP_KERNEL);
	if (strInPreamble == NULL){
		ret = -ENOMEM;
	}
	if (infilp->f_op->read(infilp, (void *)strInPreamble,
				DEFAULT_KEY_LEN, &infilp->f_pos)
		!= DEFAULT_KEY_LEN) {
		return -EIO;
	}
	printk("read the preamble in to compare %s\n", strInPreamble);
	if (memcmp(strInPreamble, preamble, DEFAULT_KEY_LEN) != 0)
		ret = -EINVAL;
	kfree(strInPreamble);
	printk("err in check preamble %d\n", ret);
	return ret;
}

static void set_blksize(int *in_blksize, int *out_blksize, int flag)
{
	if (flag == ENCRYPT) {

		*in_blksize = DEFAULT_BLK_SIZE;
		*out_blksize = *in_blksize + PAD_SIZE;
	} else {
		*in_blksize = DEFAULT_BLK_SIZE + PAD_SIZE;
		*out_blksize = DEFAULT_BLK_SIZE;
	}
}

/* I refer the pattern in the github syscall repo. Credits to: JunXing Yang
 * https://github.com/piekill/os_homework1/blob/master/xcrypt.c
 * I change the way to do encryption and decryption, way to pass and check 
 * argumnets.
 * I refer 'fs/namei.c' to write delte_partial_file using vfs_unlink.
 */



static int delete_partial_file(struct file *f)
{
	struct dentry *dentry = f->f_path.dentry;
	struct inode *dir_inode = f->f_path.dentry->d_parent->d_inode;
	int err = 0;

	filp_close(f, NULL);
	mutex_lock_nested(&(dir_inode->i_mutex), I_MUTEX_PARENT);
	if (dentry)
		if (dir_inode)
			err = vfs_unlink(dir_inode, dentry, NULL);

	mutex_unlock(&(dir_inode->i_mutex));
	return err;
}


asmlinkage long xcrypt(void *args)
{	
	struct xcrypt_args *kptr = NULL;
	int err = 0;
	void *inbuf = NULL;
	void *outbuf = NULL;
	size_t insize = 0;
	size_t outsize = 0;
	char *preamble = NULL;

	int bytes = 0;
	mm_segment_t oldfs;

	struct file *infilp = NULL, *outfilp = NULL;
	/* returns 0 for non error, -errno for corresponding errors */
	printk("xcrypt received args %p\n", args);
	err = check_args(args);
	printk("check_args return %d\n", err);
	if (err != 0)
		goto out;
	kptr = kzalloc(sizeof(*kptr), GFP_KERNEL);
	if (kptr == NULL){
		err = -ENOMEM;
		goto out;
	}

	err = set_xcrypt_args(kptr, args);
	if (err == 0)
		printk("copy arguments from user space done!\n");	
		/*	
		printk("key is %s\n", kptr->key);
        	printk("key length is %d\n", kptr->keylen);
        	printk("E/D flag is %d\n", kptr->flag);
        	printk("infile is %s\n", kptr->infile);
        	printk("outfile is %s\n", kptr->outfile);
		*/
	if (err != 0){
		pr_err("xcrypt: cannot pass arguments from user to kernel space");
		goto out_kptr;
	}

	preamble = kzalloc(DEFAULT_KEY_LEN, GFP_KERNEL);
	if (preamble == NULL) {
		err = -ENOMEM;
		goto out_kptr;
	}
	err = make_preamble(kptr, preamble);
	if (err != 0){
		pr_err("xcrypt: error in generate preamble");
		goto out_pre;
	}
	if(0 == memcmp(kptr->key,preamble,DEFAULT_KEY_LEN))
		printk("preamble create succeeded!\n");

	infilp = filp_open(kptr->infile, O_RDONLY, 0);
	if (!infilp || IS_ERR(infilp)) {
		pr_err("input file reading failed %d\n", (int) PTR_ERR(infilp));
		err = PTR_ERR(infilp);
		goto out_pre;
	}

	if (!infilp->f_op->read) {
		err = -EACCES;
		goto out_infile;/* file(system) doesn't allow reads */
	}

	infilp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	if (kptr->flag == DECRYPT) {
		if (check_preamble(infilp, preamble) != 0) {
			pr_err("xcrypt: wrong key to decrypt.\n");
			err = -EKEYREJECTED;
			printk("decrytion key invalid!\n");
			goto out_infile;
		}
	}
	/*
	* don't truncate here(O_TRUNC), truncate after verifying whether
	* infile and outfile are the same (you don't want to truncate an
	* outfile if it is also an infile).
	*/
	outfilp = filp_open(kptr->outfile, O_CREAT, S_IRUSR|S_IWUSR);
	if (!outfilp || IS_ERR(outfilp)) {
		pr_err("open output file failed %d\n", (int) PTR_ERR(outfilp));
		err = PTR_ERR(outfilp);
		goto out_outfile;
	}
	/* check whether input file and output are the same */
	if ((infilp->f_path.dentry->d_inode->i_ino
	     == outfilp->f_path.dentry->d_inode->i_ino) &&
	    (infilp->f_path.dentry->d_inode->i_sb->s_dev
	     == outfilp->f_path.dentry->d_inode->i_sb->s_dev)){
		err = -EINVAL;
		pr_err("xcrypt: infile and outfile are the same.\n");
		goto out_outfile;
	}

	/* do truncation here */
	filp_close(outfilp, NULL);
	outfilp = filp_open(kptr->outfile,
			    O_CREAT | O_WRONLY | O_TRUNC,
			    S_IRUSR|S_IWUSR);
	if (!outfilp || IS_ERR(outfilp)) {
		pr_err("write file err %d\n", (int) PTR_ERR(outfilp));
		err = PTR_ERR(outfilp);
		goto out_outfile;
	}

	if (!outfilp->f_op->write) {
		err = -EACCES;
		goto out_outfile;/* file(system) doesn't allow writes */
	}

	outfilp->f_pos = 0;

	set_blksize(&insize, &outsize, kptr->flag);
	printk("set block size returns insize %d\n outsize %d\n", insize, outsize);

	inbuf = kzalloc(insize, GFP_KERNEL);
	if (inbuf == NULL) {
		err = -ENOMEM;
		goto out_outfile;
	}

	outbuf = kzalloc(outsize, GFP_KERNEL);
	if (outbuf == NULL) {
		err = -ENOMEM;
		goto out_infilebuf;
	}

	if (kptr->flag == ENCRYPT) {
		bytes = write_preamble(outfilp, preamble, DEFAULT_KEY_LEN);
		if (bytes != DEFAULT_KEY_LEN) {
			err = -EIO;
			goto out_clean_partial_file;
		}
	}

	while ((bytes = infilp->f_op->read(infilp, inbuf,
					   insize, &infilp->f_pos)) > 0) {
		printk("insize %d\n bytes %d\n", insize, bytes);
		if (kptr->flag == ENCRYPT)
			err = aes_encrypt(kptr->key, strlen(kptr->key), outbuf, &outsize,
				      inbuf, bytes);
		else
			err = aes_decrypt(kptr->key, strlen(kptr->key), outbuf, &outsize,
				      inbuf, bytes);
		if (err != 0) {
			err = -EDOM;/* EDOM indicates en/decryption failed */
			goto out_clean_partial_file;
		}
		printk("after xcrypt outsize %d\n", outsize);
		
		bytes = outfilp->f_op->write(outfilp, outbuf,
				     outsize, &outfilp->f_pos);
		if (bytes != outsize) {
			err = -EIO;
			goto out_clean_partial_file;
		}
		memset(inbuf, 0, sizeof(inbuf));
	}

	set_fs(oldfs);
	goto out_outfilebuf;

	/*	
	buf = kzalloc(sizeof(buf_len), GFP_KERNEL);
	if (buf == NULL){
		err = -ENOMEM;
		goto out_buf;
	}
	
	// byte = wrapfs_read_file(kptr->infile, buf, buf_len);
	// printk("the buf in this page is %s\n", (char *)buf);
	// printk("The byte in read file operation is %d\n", byte);
	*/

out_clean_partial_file:
	if (delete_partial_file(outfilp))
		pr_err("failed cleaning partial file, need to delete it manually\n");
out_outfilebuf:
	kfree(outbuf);
out_infilebuf:
	kfree(inbuf);
out_outfile:
	/* may be closed in delete_partial_file(outfilp) */
	if (outfilp)
		filp_close(outfilp, NULL);
out_infile:
	filp_close(infilp, NULL);
out_pre:
	kfree(preamble);

/* out_buf:
	kfree(buf);
*/
out_kptr:
	kfree(kptr->infile);
	kfree(kptr->outfile);
	kfree(kptr->key);
	kfree(kptr);

out:
	return err;
}


/*
a secure hash/checksum of the user-level pass-phrase).  This first
section may include other information as you see fit (e.g., original file
size, and stuff for extra-credit).
*/

/*
sys_xcrypt(infile, outfile, keybuf, keylen, flags)

- missing arguments passed
- null arguments
- pointers to bad addresses
- len and buf don't match
- invalid flags
- input file cannot be opened or read
- output file cannot be opened or written
- input or output files are not regular, or they point to the same file
- trying to decrypt a file w/ the wrong key (what errno should you return?)
- ANYTHING else you can think of (the more error checking you do, the better)


After checking for these errors, you should open the input and output files
and begin copying data between the two, encrypting or decrypting the data
before it is written.


Note that the last page you write could be partially filled and that your
code should handle zero length files as well.  Also note that ciphers have a
native block size (e.g., 64 bit) and your file may have to be padded to the
cipher block size.


If no error occurred, sys_xcrypt() should return 0 to the calling process.
If an error occurred, it should return -1 and ensure that errno is set for
the calling process.



CBC only supports input and output of certain multiples (e.g., 3des uses a
64-bit block).  You will need to use padding to ensure that your input is
a multiple of the block size.


(e.g., padding with zeros doesn't work, because zeros
are a valid input file)




*/
static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("Dual BSD/GPL");



