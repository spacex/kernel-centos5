#ifndef __AES_COMPAT_H__
#define __AES_COMPAT_H__

#include <asm/scatterlist.h>

static inline void ieee80211_aes_encrypt(struct crypto_tfm *tfm,
					 const u8 pt[16], u8 ct[16])
{
	struct scatterlist src, dst;

	src.page = virt_to_page(pt);
	src.offset = offset_in_page(pt);
	src.length = AES_BLOCK_LEN;

	dst.page = virt_to_page(ct);
	dst.offset = offset_in_page(ct);
	dst.length = AES_BLOCK_LEN;

	crypto_cipher_encrypt(tfm, &dst, &src, AES_BLOCK_LEN);
}

#endif /* __AES_COMPAT_H__ */
