#
# Cryptographic API
#

proc-crypto-$(CONFIG_PROC_FS) = proc.o

obj-$(CONFIG_CRYPTO) += api.o scatterwalk.o cipher.o digest.o compress.o \
			testmgr_digest.o $(proc-crypto-y)

obj-$(CONFIG_CRYPTO_FIPS) += fips.o

crypto_algapi-objs := algapi.o ncipher.o nscatterwalk.o
obj-$(CONFIG_CRYPTO_ALGAPI) += crypto_algapi.o

obj-$(CONFIG_CRYPTO_AEAD) += aead.o

crypto_blkcipher-objs := ablkcipher.o
crypto_blkcipher-objs += blkcipher.o
obj-$(CONFIG_CRYPTO_BLKCIPHER) += crypto_blkcipher.o
obj-$(CONFIG_CRYPTO_BLKCIPHER) += chainiv.o
obj-$(CONFIG_CRYPTO_BLKCIPHER) += eseqiv.o
obj-$(CONFIG_CRYPTO_SEQIV) += seqiv.o

crypto_hash-objs := hash.o
obj-$(CONFIG_CRYPTO_HASH) += crypto_hash.o

obj-$(CONFIG_CRYPTO_API) += crypto_api.o
obj-$(CONFIG_CRYPTO_MANAGER) += cryptomgr.o
obj-$(CONFIG_CRYPTO_MANAGER) += testmgr.o
obj-$(CONFIG_CRYPTO_MANAGER) += testmgr_cipher.o
obj-$(CONFIG_CRYPTO_HMAC) += hmac_old.o
obj-$(CONFIG_CRYPTO_NHMAC) += hmac.o
obj-$(CONFIG_CRYPTO_XCBC) += xcbc.o
obj-$(CONFIG_CRYPTO_NULL) += crypto_null.o
obj-$(CONFIG_CRYPTO_MD4) += md4.o
obj-$(CONFIG_CRYPTO_MD5) += md5.o
obj-$(CONFIG_CRYPTO_SHA1) += sha1.o
obj-$(CONFIG_CRYPTO_SHA256) += sha256.o
obj-$(CONFIG_CRYPTO_SHA512) += sha512.o
obj-$(CONFIG_CRYPTO_WP512) += wp512.o
obj-$(CONFIG_CRYPTO_TGR192) += tgr192.o
obj-$(CONFIG_CRYPTO_ECB) += ecb.o
obj-$(CONFIG_CRYPTO_CBC) += cbc.o
obj-$(CONFIG_CRYPTO_CTR) += ctr.o
obj-$(CONFIG_CRYPTO_CCM) += ccm.o
obj-$(CONFIG_CRYPTO_DES) += des.o
obj-$(CONFIG_CRYPTO_BLOWFISH) += blowfish.o
obj-$(CONFIG_CRYPTO_TWOFISH) += twofish.o
obj-$(CONFIG_CRYPTO_SERPENT) += serpent.o
obj-$(CONFIG_CRYPTO_AES) += aes_generic.o
obj-$(CONFIG_CRYPTO_CAST5) += cast5.o
obj-$(CONFIG_CRYPTO_CAST6) += cast6.o
obj-$(CONFIG_CRYPTO_ARC4) += arc4.o
obj-$(CONFIG_CRYPTO_TEA) += tea.o
obj-$(CONFIG_CRYPTO_KHAZAD) += khazad.o
obj-$(CONFIG_CRYPTO_ANUBIS) += anubis.o
obj-$(CONFIG_CRYPTO_DEFLATE) += deflate.o
obj-$(CONFIG_CRYPTO_MICHAEL_MIC) += michael_mic.o
obj-$(CONFIG_CRYPTO_CRC32C) += crc32c.o
obj-$(CONFIG_CRYPTO_AUTHENC) += authenc.o
obj-$(CONFIG_CRYPTO_RNG) += rng.o
obj-$(CONFIG_CRYPTO_RNG) += krng.o
obj-$(CONFIG_CRYPTO_ANSI_CPRNG) += ansi_cprng.o
obj-$(CONFIG_CRYPTO_TEST) += tcrypt.o
obj-$(CONFIG_CRYPTO_GF128MUL) += gf128mul.o
obj-$(CONFIG_CRYPTO_XTS) += xts.o

obj-$(CONFIG_CRYPTO_SIGNATURE) += signature/
obj-$(CONFIG_CRYPTO_MPILIB) += mpi/
