/*
 * vfs491_ssl.c -- complete the VFS491 proprietary-SSLv3 handshake with our own code.
 *
 * Part of source/repos/fingerprint-sensor.  Open source; no vendor code.
 *
 * This is the successor to vfs491_session.c.  Where that tool stopped after the
 * ServerHello, this one carries the handshake through to the sensor's Finished:
 *
 *   1. unlock           GET_VERSION/GET_START_INFO, upload the two 0x06 patches
 *                       (from files *you* supply), do the two 0x1f reads
 *   2. ClientHello      self-built, tunneled as 11 <u16 LE len> <record>
 *   3. ServerHello      raw TLS on ep 0x81 (ServerHello + CertificateRequest
 *                       + ServerHelloDone)
 *   4. client flight    Certificate + ClientKeyExchange + CertificateVerify(0x0f)
 *                       in one 16 record, then ChangeCipherSpec, then the
 *                       AES-256-CBC encrypted Finished, all in one 0x11 tunnel
 *   5. verify           decrypt the sensor's CCS/Finished with the server keys
 *
 * The crypto ports the byte-exact-validated VFS495 work (reference/vfs495-linux,
 * docs/SSL_PROTOCOL.md): RSA-2048 PKCS#1 v1.5 premaster, SSLv3 MD5/SHA1 PRF,
 * SSLv3 Finished with the sender label hashed as the raw LE int (0x434c4e54 ->
 * bytes 54 4e 4c 43), and the Validity record-MAC variant that omits the length.
 *
 * The sensor's flash partition holds several RSA keys.  The client
 * Certificate carries the *client* key (storage DataID 0xc) and is echoed back;
 * the ClientKeyExchange, however, is encrypted to the *server* key
 * (DataID 0xa) -- a DIFFERENT modulus.  Pass the client key with --pubkey and
 * the server key with --cke-key.  Nothing here writes to the sensor: patches
 * land in RAM only.
 *
 * Build:  make
 * Run:    sudo ./build/vfs491_ssl P1 P2 --pubkey CERT.bin --cke-key SERVER.bin [options]
 */

#include <libusb-1.0/libusb.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define VID 0x138a
#define PID 0x003d

#define EP_CMD_OUT  0x01
#define EP_CMD_IN   0x81
#define EP_IMAGE_IN 0x82

#define CMD_GET_VERSION    0x01
#define CMD_DOWNLOAD_PATCH 0x06
#define CMD_SSL_TUNNEL     0x11
#define CMD_GET_START_INFO 0x19
#define CMD_SPI_READ       0x1f

#define TIMEOUT_MS 2000

#define MODLEN 256
#define TBUFSZ 262144

/* ------------------------------------------------------------------ utils */

static void hexdump(const char *prefix, const unsigned char *buf, int len)
{
	for (int i = 0; i < len; i += 16) {
		printf("%s%04x  ", prefix, i);
		for (int j = 0; j < 16; j++) {
			if (i + j < len)
				printf("%02x ", buf[i + j]);
			else
				printf("   ");
			if (j == 7)
				printf(" ");
		}
		printf(" |");
		for (int j = 0; j < 16 && i + j < len; j++) {
			unsigned char c = buf[i + j];
			printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
		}
		printf("|\n");
	}
}

static unsigned char *read_file(const char *path, int *lenp)
{
	FILE *f = fopen(path, "rb");
	unsigned char *buf;
	long n;

	if (!f) {
		fprintf(stderr, "cannot open %s\n", path);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (n <= 0) {
		fprintf(stderr, "%s is empty\n", path);
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n);
	if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
		fprintf(stderr, "cannot read %s\n", path);
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*lenp = (int)n;
	return buf;
}

static int randbytes(unsigned char *out, int n)
{
	FILE *f = fopen("/dev/urandom", "rb");
	if (!f)
		return -1;
	if (fread(out, 1, (size_t)n, f) != (size_t)n) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* ------------------------------------------------------------------ crypto */

static void digest(const EVP_MD *md, const unsigned char *in, int inlen,
		   unsigned char *out, unsigned *outlen)
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	EVP_DigestInit_ex(c, md, NULL);
	EVP_DigestUpdate(c, in, (size_t)inlen);
	EVP_DigestFinal_ex(c, out, outlen);
	EVP_MD_CTX_free(c);
}

/* SSLv3 PRF: out = MD5(secret || SHA1(salt || secret || seedA || seedB))
 * with salt = (i+1) bytes of 0x41+i, concatenated until n bytes. */
static void ssl3_prf(const unsigned char *secret, int slen,
		     const unsigned char *seedA, int alen,
		     const unsigned char *seedB, int blen,
		     unsigned char *out, int n)
{
	static unsigned char buf[TBUFSZ];
	int done = 0, i = 0;

	while (done < n) {
		unsigned char salt[64];
		int saltlen = i + 1;
		unsigned char sh[20], md[16];
		unsigned shl, mdl;
		int bl = 0, take;

		memset(salt, 0x41 + i, (size_t)saltlen);
		memcpy(buf + bl, salt, (size_t)saltlen); bl += saltlen;
		memcpy(buf + bl, secret, (size_t)slen);  bl += slen;
		memcpy(buf + bl, seedA, (size_t)alen);   bl += alen;
		memcpy(buf + bl, seedB, (size_t)blen);   bl += blen;
		digest(EVP_sha1(), buf, bl, sh, &shl);

		memcpy(buf, secret, (size_t)slen);
		memcpy(buf + slen, sh, 20);
		digest(EVP_md5(), buf, slen + 20, md, &mdl);

		take = (n - done < 16) ? (n - done) : 16;
		memcpy(out + done, md, (size_t)take);
		done += take;
		i++;
	}
}

/* SSLv3 Finished: 36 bytes (MD5^16 || SHA1^20).
 * The sender label is appended as raw bytes; the caller passes the LE-int
 * representation (client = 54 4e 4c 43, server = 52 56 52 53).
 *
 * `labellen` may be 0: the vendor's CertificateVerify runs the very same
 * construction (scsSSLHsHashFinish with sender 0) with NO label at all. */
static void ssl3_finished_ex(const unsigned char *master /*48*/,
			     const unsigned char *hs, int hslen,
			     const unsigned char *label, int labellen,
			     unsigned char out[36])
{
	static unsigned char buf[TBUFSZ];
	unsigned char p1[48], p2[48], inner[20], d[20];
	unsigned il, dl;
	int bl;

	/* MD5 part, pad length 48 */
	memset(p1, 0x36, 48);
	memset(p2, 0x5c, 48);
	bl = 0;
	memcpy(buf + bl, hs, (size_t)hslen); bl += hslen;
	if (labellen > 0) { memcpy(buf + bl, label, (size_t)labellen); bl += labellen; }
	memcpy(buf + bl, master, 48); bl += 48;
	memcpy(buf + bl, p1, 48); bl += 48;
	digest(EVP_md5(), buf, bl, inner, &il);
	memcpy(buf, master, 48);
	memcpy(buf + 48, p2, 48);
	memcpy(buf + 96, inner, 16);
	digest(EVP_md5(), buf, 48 + 48 + 16, d, &dl);
	memcpy(out, d, 16);

	/* SHA1 part, pad length 40 */
	memset(p1, 0x36, 40);
	memset(p2, 0x5c, 40);
	bl = 0;
	memcpy(buf + bl, hs, (size_t)hslen); bl += hslen;
	if (labellen > 0) { memcpy(buf + bl, label, (size_t)labellen); bl += labellen; }
	memcpy(buf + bl, master, 48); bl += 48;
	memcpy(buf + bl, p1, 40); bl += 40;
	digest(EVP_sha1(), buf, bl, inner, &il);
	memcpy(buf, master, 48);
	memcpy(buf + 48, p2, 40);
	memcpy(buf + 88, inner, 20);
	digest(EVP_sha1(), buf, 48 + 40 + 20, d, &dl);
	memcpy(out + 16, d, 20);
}

static void ssl3_finished(const unsigned char *master /*48*/,
			  const unsigned char *hs, int hslen,
			  const unsigned char label[4],
			  unsigned char out[36])
{
	ssl3_finished_ex(master, hs, hslen, label, 4, out);
}

static int aes256cbc_encrypt(const unsigned char key[32], const unsigned char iv[16],
			     const unsigned char *in, int inlen,
			     unsigned char *out)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int n1 = 0, n2 = 0, ok;

	ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	ok &= EVP_EncryptUpdate(ctx, out, &n1, in, inlen);
	ok &= EVP_EncryptFinal_ex(ctx, out + n1, &n2);
	EVP_CIPHER_CTX_free(ctx);
	if (!ok)
		return -1;
	return n1 + n2;
}

static int aes256cbc_decrypt(const unsigned char key[32], const unsigned char iv[16],
			     const unsigned char *in, int inlen,
			     unsigned char *out)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int n1 = 0, n2 = 0, ok;

	ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	ok &= EVP_DecryptUpdate(ctx, out, &n1, in, inlen);
	ok &= EVP_DecryptFinal_ex(ctx, out + n1, &n2);
	EVP_CIPHER_CTX_free(ctx);
	if (!ok)
		return -1;
	return n1 + n2;
}

/* MD5(transcript) || SHA1(transcript): the SSLv3 handshake hash covered by a
 * CertificateVerify.  OpenSSL signs/verifies this as NID_md5_sha1. */
static void md5_sha1(const unsigned char *in, int inlen, unsigned char *out)
{
	unsigned int l;
	EVP_MD_CTX *c = EVP_MD_CTX_new();

	EVP_DigestInit_ex(c, EVP_md5(), NULL);
	EVP_DigestUpdate(c, in, (size_t)inlen);
	EVP_DigestFinal_ex(c, out, &l);
	EVP_DigestInit_ex(c, EVP_sha1(), NULL);
	EVP_DigestUpdate(c, in, (size_t)inlen);
	EVP_DigestFinal_ex(c, out + 16, &l);
	EVP_MD_CTX_free(c);
}

static void reverse_buf(unsigned char *b, int n)
{
	int i;

	for (i = 0; i < n / 2; i++) {
		unsigned char t = b[i];
		b[i] = b[n - 1 - i];
		b[n - 1 - i] = t;
	}
}

/* Fresh RSA keypair; writes the big-endian modulus into n_be. */
static RSA *gen_rsa(unsigned char *n_be, int nlen)
{
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();
	const BIGNUM *n = NULL;

	if (!rsa || !e)
		return NULL;
	BN_set_word(e, RSA_F4);
	if (RSA_generate_key_ex(rsa, nlen * 8, e, NULL) != 1) {
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}
	RSA_get0_key(rsa, &n, NULL, NULL);
	BN_bn2binpad(n, n_be, nlen);
	BN_free(e);
	return rsa;
}

/* Load the device-provisioned client RSA private key: the decrypted DataID
 * 0x0d storage blob (1184 bytes; every integer stored little-endian):
 *   n@0x14, p@0x114, q@0x194, dmp1@0x214, dmq1@0x294, iqmp@0x314, d@0x394.
 * A PEM/DER PKCS#1 key is accepted as a fallback. */
static RSA *load_cv_key(const char *path)
{
	unsigned char *b;
	int len = 0;

	b = read_file(path, &len);
	if (!b)
		return NULL;
	/* Raw slot blob: DER starts with 0x30, PEM with '-'. */
	if (len >= 0x494 && b[0] != 0x30 && b[0] != '-') {
		BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
		RSA *r;

		n    = BN_lebin2bn(b + 0x14,  0x100, NULL);
		p    = BN_lebin2bn(b + 0x114, 0x80,  NULL);
		q    = BN_lebin2bn(b + 0x194, 0x80,  NULL);
		dmp1 = BN_lebin2bn(b + 0x214, 0x80,  NULL);
		dmq1 = BN_lebin2bn(b + 0x294, 0x80,  NULL);
		iqmp = BN_lebin2bn(b + 0x314, 0x80,  NULL);
		d    = BN_lebin2bn(b + 0x394, 0x100, NULL);
		e    = BN_new();
		r    = RSA_new();
		free(b);
		if (!n || !p || !q || !dmp1 || !dmq1 || !iqmp || !d || !e || !r)
			return NULL;
		BN_set_word(e, RSA_F4);
		if (RSA_set0_key(r, n, e, d) != 1 ||
		    RSA_set0_factors(r, p, q) != 1 ||
		    RSA_set0_crt_params(r, dmp1, dmq1, iqmp) != 1)
			return NULL;
		return r;
	}
	{
		BIO *bio = BIO_new_mem_buf(b, len);
		RSA *r = NULL;
		if (bio) {
			r = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
			BIO_free(bio);
			if (!r) {
				bio = BIO_new_mem_buf(b, len);
				r = d2i_RSAPrivateKey_bio(bio, NULL);
				BIO_free(bio);
			}
		}
		free(b);
		return r;
	}
}

/* Raw RSA PKCS#1 v1.5 signature over `dig` (type 1, no DigestInfo header):
 * exactly what the vendor stack emits for the 0x0f CertificateVerify.
 * Output is standard big-endian (as it appears on the wire). */
static int raw_pkcs1_sign(RSA *r, const unsigned char *dig, int diglen,
			  unsigned char *out)
{
	int k = RSA_size(r);
	unsigned char em[512];
	int i, padlen = k - 3 - diglen;

	if (k <= 3 + diglen || k > (int)sizeof(em))
		return -1;
	em[0] = 0x00;
	em[1] = 0x01;
	for (i = 0; i < padlen; i++)
		em[2 + i] = 0xff;
	em[2 + padlen] = 0x00;
	memcpy(em + 3 + padlen, dig, (size_t)diglen);
	return RSA_private_encrypt(k, em, out, r, RSA_NO_PADDING);
}

/* RSA PKCS#1 v1.5 type-2 encrypt a short message.  `le` selects whether the
 * stored modulus buffer is read as a little-endian integer (VFS495 uses LE).
 * The wire ciphertext is big-endian, exactly like the sensor's. */
static int rsa_pkcs1_encrypt(const unsigned char *mod, int modlen, int le,
			     const unsigned char *msg, int msglen,
			     unsigned char *out)
{
	BIGNUM *n = le ? BN_lebin2bn(mod, modlen, NULL) : BN_bin2bn(mod, modlen, NULL);
	BIGNUM *e = BN_new();
	BIGNUM *m = BN_new();
	BIGNUM *c = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	unsigned char em[MODLEN];
	int pslen = modlen - 3 - msglen, i, ret = -1;

	if (!n || !e || !m || !c || !ctx || pslen < 8)
		goto out;

	em[0] = 0x00;
	em[1] = 0x02;
	{
		/* One read, not one fopen per byte: latency between the
		 * ServerHello and the client flight is suspected to matter. */
		unsigned char ps[MODLEN];
		if (pslen > MODLEN || randbytes(ps, pslen) < 0)
			goto out;
		for (i = 0; i < pslen; i++)
			em[2 + i] = ps[i] ? ps[i] : 0x01;  /* PKCS#1 PS != 0 */
	}
	em[2 + pslen] = 0x00;
	memcpy(em + 3 + pslen, msg, (size_t)msglen);

	BN_set_word(e, 0x10001);
	BN_bin2bn(em, modlen, m);
	if (!BN_mod_exp(c, m, e, n, ctx))
		goto out;
	if (BN_bn2binpad(c, out, modlen) != modlen)
		goto out;
	ret = 0;
out:
	BN_free(n); BN_free(e); BN_free(m); BN_free(c); BN_CTX_free(ctx);
	return ret;
}

/* ------------------------------------------------------------------ record */

struct conn {
	unsigned char cmac[20], smac[20];
	unsigned char ckey[32], skey[32];
	unsigned char civ[16],  siv[16];
	uint64_t send_seq, recv_seq;
};

/* Validity SSLv3 record MAC variant: header is seq(8) + type(1), no length. */
static void rec_mac(const unsigned char key[20], uint64_t seq, unsigned char type,
		    const unsigned char *data, int len, unsigned char out[20])
{
	static unsigned char buf[TBUFSZ];
	unsigned char p1[40], p2[40], inner[20];
	unsigned il;
	int bl = 0;

	memset(p1, 0x36, 40);
	memset(p2, 0x5c, 40);
	memcpy(buf + bl, key, 20); bl += 20;
	memcpy(buf + bl, p1, 40); bl += 40;
	for (int i = 0; i < 8; i++)
		buf[bl++] = (unsigned char)(seq >> (56 - 8 * i));
	buf[bl++] = type;
	memcpy(buf + bl, data, (size_t)len); bl += len;
	digest(EVP_sha1(), buf, bl, inner, &il);

	bl = 0;
	memcpy(buf + bl, key, 20); bl += 20;
	memcpy(buf + bl, p2, 40); bl += 40;
	memcpy(buf + bl, inner, 20); bl += 20;
	digest(EVP_sha1(), buf, bl, out, &il);
}

/* Encrypt one record (TLS 5-byte header + AES-256-CBC ciphertext). */
static int seal_record(struct conn *c, unsigned char type,
		       const unsigned char *data, int len, unsigned char *out)
{
	static unsigned char mac[20];
	static unsigned char body[TBUFSZ];
	static unsigned char ct[TBUFSZ];
	int bl = 0, padlen, ctl;

	rec_mac(c->cmac, c->send_seq, type, data, len, mac);
	c->send_seq++;

	memcpy(body, data, (size_t)len); bl = len;
	memcpy(body + bl, mac, 20); bl += 20;
	padlen = 16 - (bl % 16);
	memset(body + bl, padlen - 1, (size_t)padlen); bl += padlen;

	ctl = aes256cbc_encrypt(c->ckey, c->civ, body, bl, ct);
	if (ctl < 0)
		return -1;
	memcpy(c->civ, ct + ctl - 16, 16);

	out[0] = type; out[1] = 0x03; out[2] = 0x00;
	out[3] = (unsigned char)(ctl >> 8); out[4] = (unsigned char)ctl;
	memcpy(out + 5, ct, (size_t)ctl);
	return 5 + ctl;
}

/* Decrypt one record body in place (returns plaintext length, or -1). */
static int open_record(struct conn *c, unsigned char type,
		       const unsigned char *ct, int ctlen, unsigned char *out)
{
	static unsigned char pt[TBUFSZ];
	static unsigned char mac[20];
	int n = aes256cbc_decrypt(c->skey, c->siv, ct, ctlen, pt);
	int padlen, datalen;

	if (n < 0)
		return -1;
	padlen = pt[n - 1] + 1;
	datalen = n - 20 - padlen;
	if (datalen < 0 || datalen > n)
		return -1;
	rec_mac(c->smac, c->recv_seq, type, pt, datalen, mac);
	c->recv_seq++;
	memcpy(c->siv, ct + ctlen - 16, 16);
	if (memcmp(mac, pt + datalen, 20) != 0)
		return -1;   /* MAC mismatch (wrong keys or not our record) */
	memcpy(out, pt, (size_t)datalen);
	return datalen;
}

/* ------------------------------------------------------------------ usb */

static int read_all(libusb_device_handle *h, unsigned char ep,
		    unsigned char *out, int cap, unsigned timeout_ms)
{
	int total = 0;

	while (total < cap) {
		int got = 0;
		unsigned t = total ? 20 : timeout_ms;
		int r = libusb_bulk_transfer(h, ep, out + total, cap - total, &got, t);
		if (r == LIBUSB_ERROR_TIMEOUT || r == LIBUSB_ERROR_PIPE)
			break;
		if (r < 0) {
			fprintf(stderr, "  bulk IN failed: %s\n", libusb_error_name(r));
			return -1;
		}
		if (got == 0)
			break;
		total += got;
	}
	return total;
}

static int send_cmd(libusb_device_handle *h, const unsigned char *cmd, int len,
		    unsigned char *reply, int cap)
{
	int xfer = 0;
	int r = libusb_bulk_transfer(h, EP_CMD_OUT, (unsigned char *)cmd, len,
				     &xfer, TIMEOUT_MS);
	if (r < 0) {
		fprintf(stderr, "  bulk OUT failed: %s\n", libusb_error_name(r));
		return -1;
	}
	return read_all(h, EP_CMD_IN, reply, cap, TIMEOUT_MS);
}

/* If a previous run left bytes unread on an IN endpoint the sensor's command
 * engine stalls every later OUT with LIBUSB_ERROR_TIMEOUT.  Drain anything
 * stale on the two IN endpoints so the tool recovers without a replug. */
static void drain(libusb_device_handle *h)
{
	unsigned char tmp[8192];
	unsigned char eps[2] = {EP_CMD_IN, EP_IMAGE_IN};
	int e, i;

	for (e = 0; e < 2; e++) {
		for (i = 0; i < 16; i++) {
			int got = 0;
			int r = libusb_bulk_transfer(h, eps[e], tmp, sizeof(tmp),
						     &got, 100);
			if (r < 0 || got == 0)
				break;
		}
	}
}

/* A rejected handshake leaves the sensor's bulk-OUT endpoint halted, so the
 * next transfer returns LIBUSB_ERROR_PIPE.  Clear the halts and drain so a
 * second attempt gets a fair, clean try. */
static void reset_pipe(libusb_device_handle *h)
{
	libusb_clear_halt(h, EP_CMD_OUT);
	libusb_clear_halt(h, EP_CMD_IN);
	libusb_clear_halt(h, EP_IMAGE_IN);
	drain(h);
}

static void cmd_get_version(libusb_device_handle *h)
{
	unsigned char cmd[1] = {CMD_GET_VERSION};
	unsigned char r[4096];
	int n = send_cmd(h, cmd, 1, r, sizeof(r));

	printf("GET_VERSION (0x01)\n");
	if (n < 31) {
		printf("  no/short reply (%d bytes)\n", n);
		return;
	}
	printf("  version %u.%u build %u, patch flag 0x%02x, patch signature 0x%08x%s\n",
	       r[10], r[11],
	       r[6] | (r[7] << 8) | (r[8] << 16) | ((unsigned)r[9] << 24),
	       r[17], r[26] | (r[27] << 8) | (r[28] << 16) | ((unsigned)r[29] << 24),
	       r[17] ? "  (patches loaded)" : "  (no patch loaded)");
}

static const unsigned char spi_read_1[] = {
	0x1f, 0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f,
};
static const unsigned char spi_read_2[] = {	0x1f, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x10, 0x00, 0x00,
};

static const char *g_spi_dump = NULL;   /* --spi-dump PREFIX: save the 0x1f reads */

static void dump_to_file(const char *suffix, const unsigned char *buf, int len)
{
	char path[512];
	FILE *f;

	if (!g_spi_dump || len <= 0)
		return;
	snprintf(path, sizeof(path), "%s%s.bin", g_spi_dump, suffix);
	f = fopen(path, "wb");
	if (!f) {
		fprintf(stderr, "  cannot write %s\n", path);
		return;
	}
	fwrite(buf, 1, (size_t)len, f);
	fclose(f);
	printf("   saved %d bytes to %s\n", len, path);
}

static void do_patch(libusb_device_handle *h, const char *label, const char *path)
{
	unsigned char r[4096];
	unsigned char *cmd;
	int len = 0, n;
	unsigned char *buf;

	cmd = read_file(path, &len);
	if (!cmd)
		return;
	buf = malloc((size_t)len + 1);
	if (!buf) {
		free(cmd);
		return;
	}
	buf[0] = CMD_DOWNLOAD_PATCH;
	memcpy(buf + 1, cmd, (size_t)len);
	n = send_cmd(h, buf, len + 1, r, sizeof(r));
	free(buf);
	free(cmd);
	printf("%s DOWNLOAD_PATCH (%d bytes): ", label, len);
	if (n >= 2)
		printf("status 0x%04x\n", r[0] | (r[1] << 8));
	else
		printf("no reply (%d)\n", n);
}

static int unlock(libusb_device_handle *h, const char *p1, const char *p2, int spi)
{
	unsigned char r[4096];      /* GET_START_INFO replies are 68 bytes! */
	unsigned char data[8192];
	int n;

	cmd_get_version(h);

	n = send_cmd(h, (const unsigned char[]){CMD_GET_START_INFO}, 1, r, sizeof(r));
	printf("GET_START_INFO (0x19)\n");
	if (n >= 2) {
		printf("  status 0x%04x, %d bytes\n", r[0] | (r[1] << 8), n);
		hexdump("   ", r, n);
	} else {
		printf("  no/short reply (%d bytes)\n", n);
	}

	do_patch(h, "patch #1", p1);
	cmd_get_version(h);
	if (spi) {
		n = send_cmd(h, spi_read_1, sizeof(spi_read_1), r, sizeof(r));
		printf("1f read #1: status 0x%04x, ", n >= 2 ? r[0] | (r[1] << 8) : 0);
		n = read_all(h, EP_IMAGE_IN, data, 128, 1500);
		printf("%d bytes on 0x82\n", n);
		dump_to_file("1", data, n);
		/* The sensor needs ~12 ms between the two reads (it is finishing the
		 * flash op for #1); sending #2 too early yields status 0x0000 but no
		 * data and then stalls the command pipe. */
		usleep(30000);
		n = send_cmd(h, spi_read_2, sizeof(spi_read_2), r, sizeof(r));
		printf("1f read #2: status 0x%04x, ", n >= 2 ? r[0] | (r[1] << 8) : 0);
		n = read_all(h, EP_IMAGE_IN, data, 4096, 1500);
		printf("%d bytes on 0x82\n", n);
		dump_to_file("2", data, n);
		/* Recover if the sensor halted the command pipe (e.g. it streamed
		 * data we did not drain); the handshake must still be able to run. */
		libusb_clear_halt(h, EP_CMD_OUT);
		libusb_clear_halt(h, EP_CMD_IN);
	}
	do_patch(h, "patch #2", p2);
	cmd_get_version(h);
	return 0;
}

/* ------------------------------------------------------------------ handshake */

static int build_clienthello(unsigned char *rec, const unsigned char random[32])
{
	unsigned char body[64];
	int n = 0, m = 0;

	body[n++] = 0x03; body[n++] = 0x00;
	memcpy(body + n, random, 32); n += 32;
	body[n++] = 7;
	memset(body + n, 0, 7); n += 7;      /* 7 zero bytes, as the vendor sends */
	body[n++] = 0x00; body[n++] = 0x06;
	body[n++] = 0x00; body[n++] = 0x44;
	body[n++] = 0x00; body[n++] = 0x43;
	body[n++] = 0x00; body[n++] = 0x42;
	body[n++] = 0x00;

	rec[m++] = 0x16; rec[m++] = 0x03; rec[m++] = 0x00;
	rec[m++] = (unsigned char)((4 + n) >> 8);
	rec[m++] = (unsigned char)(4 + n);
	rec[m++] = 0x01; rec[m++] = 0x00; rec[m++] = 0x00;
	rec[m++] = (unsigned char)n;
	memcpy(rec + m, body, (size_t)n); m += n;
	return m;
}

struct hs_opt {
	int modle;          /* modulus buffer is little-endian */
	const unsigned char *cv;   /* NULL => 256 zero bytes */
	int have_cert;
	int have_cv;
	int do_app;
	const char *app_hex;  /* --cmd HEX: VCSFW command sent as encrypted AppData */
	int do_image;         /* --image: after --cmd, read plaintext frames from EP 0x82 */
	const char *image_out;/* --image-out FILE: where to save the EP 0x82 stream */
	int cv_mode;   /* 0 zeros | 1 file(o->cv) | 2 RSA(premaster) | 3 RSA(random)
			* | 4 sign transcript with a fresh key we present
			* | 5 vendor CertificateVerify: master-keyed SSLv3 hash,
			*     raw PKCS#1, signed with o->cvkey (DataID 0x0d) */
	int cv_rev;    /* byte-reverse the signed 0x0f body (as the vendor does) */
	RSA *cvkey;    /* device-provisioned client private key (cv_mode 5) */
	/* The sensor uses TWO distinct RSA keys: the Certificate carries the
	 * client key (storage DataID 0xc) while the ClientKeyExchange is
	 * encrypted to the server key (DataID 0xa).  When ckemod is NULL the
	 * Certificate key is reused for the CKE (the old, wrong behaviour). */
	const unsigned char *ckemod;
	int ckemodle;
};

static int handshake(libusb_device_handle *h, const unsigned char *mod, int modlen,
		     struct hs_opt *o)
{
	unsigned char random[32], srandom[32], premaster[48];
	unsigned char ch_rec[128], ch_hs[128], tunnel[TBUFSZ];
	unsigned char resp[TBUFSZ];
	unsigned char enc[MODLEN];
	unsigned char cert_hs[MODLEN + 32], cke_hs[256 + 4], cv_hs[256 + 4];
	unsigned char rec1[TBUFSZ], flight[TBUFSZ];
	unsigned char master[48], keyblock[136];
	unsigned char hs[4096], fin_body[36];
	unsigned char ccs[6] = {0x14, 0x03, 0x00, 0x00, 0x01, 0x01};
	struct conn c;
	int ch_reclen, sh_reclen, ch_hslen, sh_hslen, p, n, len, hslen;
	int cert_len, cke_len, cv_len, r1, fin, verified = 0;
	unsigned char ownmod[MODLEN];
	RSA *ownrsa = NULL;
	const unsigned char *cm = o->ckemod ? o->ckemod : mod;
	int cmle = o->ckemod ? o->ckemodle : o->modle;

	if (randbytes(random, 32) < 0 || randbytes(premaster, 48) < 0)
		return -1;
	premaster[0] = 0x03;
	premaster[1] = 0x00;

	if (o->cv_mode == 4) {
		ownrsa = gen_rsa(ownmod, MODLEN);
		if (!ownrsa) {
			printf("RSA key generation failed\n");
			return -1;
		}
		/* The vendor copies the modulus into the Certificate verbatim
		 * from flash, which our model reads little-endian; emit ours the
		 * same way so the sensor parses the number we actually signed. */
		if (o->modle)
			reverse_buf(ownmod, MODLEN);
		printf("   Certificate carries our own fresh RSA-2048 key (%s endian)\n",
		       o->modle ? "little" : "big");
	}

	/* --- ClientHello --- */
	ch_reclen = build_clienthello(ch_rec, random);
	ch_hslen = ch_reclen - 5;
	memcpy(ch_hs, ch_rec + 5, (size_t)ch_hslen);
	tunnel[0] = CMD_SSL_TUNNEL;
	tunnel[1] = (unsigned char)(ch_reclen & 0xff);
	tunnel[2] = (unsigned char)((ch_reclen >> 8) & 0xff);
	memcpy(tunnel + 3, ch_rec, (size_t)ch_reclen);
	printf("-> ClientHello (%d-byte record)\n", ch_reclen);
	n = send_cmd(h, tunnel, 3 + ch_reclen, resp, sizeof(resp));
	if (n < 5 || resp[0] != 0x16 || resp[5] != 0x02) {
		printf("<- no ServerHello (n=%d, first=0x%02x)\n", n, n > 0 ? resp[0] : 0);
		if (n >= 7 && resp[0] == 0x15)
			printf("   ALERT level %u desc 0x%02x\n", resp[5], resp[6]);
		return -1;
	}
	sh_reclen = (resp[3] << 8) | resp[4];
	sh_hslen = sh_reclen;
	/* Raw TLS record layout on ep 0x81:
	 *   [0] type [1..2] ver [3..4] rec len [5] hs type [6..8] hs len
	 *   [9..10] ver [11..42] server_random ...
	 * The random is at offset 11.  (An earlier version read resp+6, i.e.
	 * the handshake length + version bytes, producing a garbage
	 * server_random -- hence a master secret the sensor could never match
	 * (it has the real one), hence the fatal alert 0x2f.) */
	if (sh_reclen < 43) {
		printf("<- ServerHello too short (%d)\n", sh_reclen);
		return -1;
	}
	memcpy(srandom, resp + 11, 32);
	printf("<- ServerHello record=%d bytes\n", sh_reclen);
	{
		int sidlen = resp[43];
		printf("   suite=0x%02x%02x compression=0x%02x sid=",
		       resp[51], resp[52], resp[53]);
		if (sidlen > 0 && sidlen < 32)
			fwrite(resp + 44, 1, (size_t)sidlen, stdout);
		printf("\n");
	}
	printf("   server_random=");
	for (p = 0; p < 32; p++)
		printf("%02x", srandom[p]);
	printf("\n   client_random=");
	for (p = 0; p < 32; p++)
		printf("%02x", random[p]);
	printf("\n");
	if (sh_reclen + 5 > n) {
		printf("   (short server flight)\n");
		return -1;
	}

	/* --- client flight messages --- */
	len = 0;
	if (o->have_cert) {
		/* Certificate: 00 01 15 00 01 08 00 01 00 00 01 00 01 00 || modulus */
		cert_hs[0] = 0x0b; cert_hs[1] = 0x00; cert_hs[2] = 0x01; cert_hs[3] = 0x0e;
		memcpy(cert_hs + 4, (const unsigned char[]){0x00,0x01,0x15,0x00,0x01,0x08,
			0x00,0x01,0x00,0x00,0x01,0x00,0x01,0x00}, 14);
		memcpy(cert_hs + 18, ownrsa ? ownmod : mod, (size_t)modlen);
		cert_len = 18 + modlen;
		len += cert_len;
	} else {
		cert_len = 0;
	}

	if (rsa_pkcs1_encrypt(cm, modlen, cmle, premaster, 48, enc) < 0) {
		printf("RSA encrypt failed\n");
		return -1;
	}
	cke_hs[0] = 0x10; cke_hs[1] = 0x00; cke_hs[2] = 0x01; cke_hs[3] = 0x00;
	memcpy(cke_hs + 4, enc, (size_t)modlen);
	cke_len = 4 + modlen;
	len += cke_len;

	if (o->have_cv) {
		cv_hs[0] = 0x0f; cv_hs[1] = 0x00; cv_hs[2] = 0x01; cv_hs[3] = 0x00;
		if (o->cv_mode == 2) {
			/* Second RSA blob = the premaster again: tests whether the
			 * 0x0f must decrypt to the same premaster as the CKE. */
			if (rsa_pkcs1_encrypt(mod, modlen, o->modle, premaster, 48,
					      cv_hs + 4) < 0)
				return -1;
		} else if (o->cv_mode == 3) {
			/* A well-formed PKCS#1 block of unrelated content: tests
			 * whether the sensor validates only the block form. */
			unsigned char rnd[48];
			if (randbytes(rnd, 48) < 0)
				return -1;
			rnd[0] = 0x03; rnd[1] = 0x00;
			if (rsa_pkcs1_encrypt(mod, modlen, o->modle, rnd, 48,
					      cv_hs + 4) < 0)
				return -1;
		} else if (o->cv_mode == 4) {
			/* Sign the transcript with the fresh key whose modulus we
			 * just put in the Certificate: proves whether the sensor
			 * trusts the client certificate we present. */
			unsigned char dig[36], sig[512];
			unsigned int sl = 0;
			int tl = 0;

			memcpy(hs + tl, ch_hs, (size_t)ch_hslen); tl += ch_hslen;
			memcpy(hs + tl, resp + 5, (size_t)sh_hslen); tl += sh_hslen;
			if (cert_len) {
				memcpy(hs + tl, cert_hs, (size_t)cert_len);
				tl += cert_len;
			}
			memcpy(hs + tl, cke_hs, (size_t)cke_len); tl += cke_len;
			md5_sha1(hs, tl, dig);
			if (!ownrsa ||
			    RSA_sign(NID_md5_sha1, dig, 36, sig, &sl, ownrsa) != 1) {
				printf("CertificateVerify signing failed\n");
				return -1;
			}
			if (o->cv_rev)
				reverse_buf(sig, (int)sl);
			memcpy(cv_hs + 4, sig, 256);
			RSA_free(ownrsa);
			ownrsa = NULL;
		} else if (o->cv_mode == 5) {
			/* Faithful vendor CertificateVerify.  The sensor's
			 * scsSSLHsHashFinish runs the SSLv3 Finished
			 * construction keyed by the master secret, but with an
			 * EMPTY sender label for the 0x0f.  The 36-byte digest is
			 * then signed raw (PKCS#1 type 1, NO DigestInfo) by the
			 * device-provisioned client key (storage DataID 0x0d),
			 * whose modulus the sensor knows independently -- the
			 * Certificate still carries DataID 0xc, exactly as the
			 * vendor presents it. */
			unsigned char dig[36], sig[512], m2[48];
			int tl = 0;

			if (!o->cvkey) {
				printf("CertificateVerify: no --cv-key loaded\n");
				return -1;
			}
			ssl3_prf(premaster, 48, random, 32, srandom, 32, m2, 48);
			memcpy(hs + tl, ch_hs, (size_t)ch_hslen); tl += ch_hslen;
			memcpy(hs + tl, resp + 5, (size_t)sh_hslen); tl += sh_hslen;
			if (cert_len) {
				memcpy(hs + tl, cert_hs, (size_t)cert_len);
				tl += cert_len;
			}
			memcpy(hs + tl, cke_hs, (size_t)cke_len); tl += cke_len;
			ssl3_finished_ex(m2, hs, tl, NULL, 0, dig);
			printf("   CertificateVerify digest (MD5||SHA1): ");
			for (tl = 0; tl < 36; tl++)
				printf("%02x", dig[tl]);
			printf("\n");
			if (raw_pkcs1_sign(o->cvkey, dig, 36, sig) < 0) {
				printf("CertificateVerify signing failed\n");
				return -1;
			}
			if (o->cv_rev)
				reverse_buf(sig, 256);
			memcpy(cv_hs + 4, sig, 256);
		} else if (o->cv) {
			memcpy(cv_hs + 4, o->cv, 256);
		} else {
			memset(cv_hs + 4, 0, 256);
		}
		cv_len = 4 + 256;
		len += cv_len;
	} else {
		cv_len = 0;
	}

	/* one 16 record carrying all three messages */
	r1 = 0;
	rec1[r1++] = 0x16; rec1[r1++] = 0x03; rec1[r1++] = 0x00;
	rec1[r1++] = (unsigned char)(len >> 8); rec1[r1++] = (unsigned char)len;
	if (cert_len) { memcpy(rec1 + r1, cert_hs, (size_t)cert_len); r1 += cert_len; }
	memcpy(rec1 + r1, cke_hs, (size_t)cke_len); r1 += cke_len;
	if (cv_len) { memcpy(rec1 + r1, cv_hs, (size_t)cv_len); r1 += cv_len; }

	/* --- keys --- */
	ssl3_prf(premaster, 48, random, 32, srandom, 32, master, 48);
	ssl3_prf(master, 48, srandom, 32, random, 32, keyblock, 136);
	memcpy(c.cmac, keyblock + 0, 20);
	memcpy(c.smac, keyblock + 20, 20);
	memcpy(c.ckey, keyblock + 40, 32);
	memcpy(c.skey, keyblock + 72, 32);
	memcpy(c.civ, keyblock + 104, 16);
	memcpy(c.siv, keyblock + 120, 16);
	c.send_seq = c.recv_seq = 0;

	/* transcript so far: ClientHello, server flight (SH+CertReq+SHDone) */
	hslen = 0;
	memcpy(hs + hslen, ch_hs, (size_t)ch_hslen); hslen += ch_hslen;
	memcpy(hs + hslen, resp + 5, (size_t)sh_hslen); hslen += sh_hslen;
	if (cert_len) { memcpy(hs + hslen, cert_hs, (size_t)cert_len); hslen += cert_len; }
	memcpy(hs + hslen, cke_hs, (size_t)cke_len); hslen += cke_len;
	if (cv_len) { memcpy(hs + hslen, cv_hs, (size_t)cv_len); hslen += cv_len; }

	ssl3_finished(master, hs, hslen, (const unsigned char[]){0x54,0x4e,0x4c,0x43},
		      fin_body);

	/* --- Finished record (sealed now: it is the first record under the new
	 *     cipher spec, so its MAC sequence number is 0) --- */
	{
		unsigned char fin_hs[40];
		unsigned char finrec[256];
		fin_hs[0] = 0x14; fin_hs[1] = 0x00; fin_hs[2] = 0x00; fin_hs[3] = 0x24;
		memcpy(fin_hs + 4, fin_body, 36);
		fin = seal_record(&c, 0x16, fin_hs, 40, finrec);
		if (fin < 0) {
			printf("record seal failed\n");
			return -1;
		}
		/* second tunnel, exactly like the vendor: record1 || CCS || Finished */
		memcpy(flight, rec1, (size_t)r1);
		len = r1;
		memcpy(flight + len, ccs, 6); len += 6;
		memcpy(flight + len, finrec, (size_t)fin); len += fin;
	}

	{
		unsigned char *t = malloc((size_t)len + 3);
		t[0] = CMD_SSL_TUNNEL;
		t[1] = (unsigned char)(len & 0xff);
		t[2] = (unsigned char)((len >> 8) & 0xff);
		memcpy(t + 3, flight, (size_t)len);
		printf("-> client flight: Certificate=%d CKE=%d CV=%d + CCS + Finished"
		       "  (tunnel %d bytes)\n", cert_len, cke_len, cv_len, len);
		n = send_cmd(h, t, len + 3, resp, sizeof(resp));
		free(t);
	}
	printf("<- reply: %d bytes\n", n);
	if (n <= 0)
		return -1;
	hexdump("   ", resp, n > 160 ? 160 : n);

	if (resp[0] == 0x15) {
		printf("   ALERT level %u desc 0x%02x  -> handshake rejected\n",
		       n > 5 ? resp[5] : 0, n > 6 ? resp[6] : 0);
		return -1;
	}
	if (resp[0] != 0x14 && resp[0] != 0x16 && resp[0] != 0x17) {
		printf("   not a TLS record (0x%02x)\n", resp[0]);
		return -1;
	}

	/* --- parse the server flight: CCS + Finished (+ appdata) --- */
	p = 0;
	while (p + 5 <= n) {
		unsigned char rt = resp[p];
		int rl = (resp[p + 3] << 8) | resp[p + 4];
		unsigned char *body = resp + p + 5;

		if (p + 5 + rl > n)
			break;
		if (rt == 0x14) {
			printf("   [CCS] change_cipher_spec\n");
		} else if (rt == 0x16) {
			unsigned char plain[TBUFSZ];
			int pl = open_record(&c, rt, body, rl, plain);
			if (pl >= 4 && plain[0] == 0x14) {
				unsigned char expect[36];
				/*
				 * Server Finished: same SSLv3 Finished construction as
				 * the client's, keyed by the master secret, with the
				 * server sender label.  Crucially the vendor's
				 * scsSSLHandshakeHeaderWrite (0x513320) skips
				 * scsSSLHsHashUpdate for handshake type 0x14, so NO
				 * Finished message is ever folded into the transcript:
				 * the digest covers the handshake through the
				 * CertificateVerify only (client Finished excluded).
				 */
				printf("   [Finished] decrypted %d bytes, verify=", pl);
				ssl3_finished(master, hs, hslen,
					      (const unsigned char[]){0x52,0x56,0x52,0x53},
					      expect);
				if (pl == 40 && memcmp(plain + 4, expect, 36) == 0) {
					verified = 1;
					printf("OK (keys agree!)\n");
				} else {
					printf("MISMATCH\n");
				}
			} else {
				printf("   [0x16] decrypt failed or unexpected\n");
			}
		} else if (rt == 0x17) {
			unsigned char plain[TBUFSZ];
			int pl = open_record(&c, rt, body, rl, plain);
			printf("   [AppData] %d ciphertext -> %d plaintext\n", rl, pl);
			if (pl > 0)
				hexdump("      ", plain, pl > 64 ? 64 : pl);
		} else {
			printf("   [0x%02x] %d bytes\n", rt, rl);
		}
		p += 5 + rl;
	}

	/* --- optionally send an encrypted VCSFW command as AppData --- */
	if (o->do_app || o->app_hex) {
		unsigned char payload[512];
		int plen = 0;
		if (o->app_hex) {
			const char *s = o->app_hex;
			while (*s && plen < (int)sizeof(payload)) {
				while (*s == ' ' || *s == ':') s++;
				if (!*s) break;
				unsigned int b;
				if (sscanf(s, "%2x", &b) != 1) {
					fprintf(stderr, "bad --cmd hex near '%s'\n", s);
					return -1;
				}
				payload[plen++] = (unsigned char)b;
				s += 2;
			}
		} else {
			payload[plen++] = 0x01;  /* GET_VERSION */
		}
		{
			unsigned char apprec[TBUFSZ];
			int al = seal_record(&c, 0x17, payload, plen, apprec);
			printf("-> AppData cmd (%d bytes plaintext):\n", plen);
			hexdump("      ", payload, plen);
			n = send_cmd(h, apprec, al, resp, sizeof(resp));
			printf("<- %d bytes\n", n);
			if (n > 5 && resp[0] == 0x17) {
				unsigned char plain[TBUFSZ];
				int pl = open_record(&c, 0x17, resp + 5,
						     (resp[3] << 8) | resp[4], plain);
				printf("   decrypted %d bytes:\n", pl);
				if (pl > 0)
					hexdump("      ", plain, pl > 256 ? 256 : pl);
			}
			/* one short drain for any trailing control reply */
			{
				unsigned char extra[TBUFSZ];
				int en = read_all(h, EP_CMD_IN, extra, sizeof(extra), 300);
				if (en > 5 && extra[0] == 0x17) {
					unsigned char plain[TBUFSZ];
					int pl = open_record(&c, 0x17, extra + 5,
							     (extra[3] << 8) | extra[4], plain);
					printf("   [extra control] %d bytes:\n", en);
					if (pl > 0)
						hexdump("      ", plain, pl > 256 ? 256 : pl);
				}
			}
		}
	}

	/* --- optionally read the plaintext image stream from EP 0x82 --- */
	if (o->do_image) {
		struct timespec t0, tn;
		long waited_ms;
		int total = 0, frames = 0;
		FILE *ifp = o->image_out ? fopen(o->image_out, "wb") : NULL;
		if (o->image_out)
			printf("-> saving EP 0x82 stream to %s\n", o->image_out);
		printf("-> reading image frames from EP 0x82 "
		       "(30 s window; swipe the sensor now) ...\n");
		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (;;) {
			unsigned char img[16384];
			int r = 0;
			int ret = libusb_bulk_transfer(h, EP_IMAGE_IN, img, sizeof(img),
						       &r, 1000);
			if (ret == 0 && r > 0) {
				total += r;
				frames++;
				if (ifp)
					fwrite(img, 1, (size_t)r, ifp);
				if (frames <= 8)
					hexdump("      img ", img, r > 64 ? 64 : r);
				if (total > 8 * 1024 * 1024)
					break;
				continue;
			}
			/* a timeout just means "no frame yet": keep waiting */
			if (ret != 0 && ret != LIBUSB_ERROR_TIMEOUT)
				break;
			clock_gettime(CLOCK_MONOTONIC, &tn);
			waited_ms = (tn.tv_sec - t0.tv_sec) * 1000L +
				    (tn.tv_nsec - t0.tv_nsec) / 1000000L;
			if (waited_ms > 30000)
				break;
		}
		if (ifp)
			fclose(ifp);
		printf("   image: %d frames, %d bytes total\n", frames, total);
	}
	return verified ? 1 : 0;
}

/* ------------------------------------------------------------------ main */

static void selftest(void)
{
	unsigned char pm[48], cr[32], sr[32], master[48], kb[136], fin[36];
	unsigned char hs[64], fin_hs[40], rec[256];
	struct conn c;
	int i, rl;

	for (i = 0; i < 48; i++) pm[i] = (unsigned char)i;
	pm[0] = 0x03; pm[1] = 0x00;
	for (i = 0; i < 32; i++) { cr[i] = (unsigned char)(0x10 + i); sr[i] = (unsigned char)(0x80 + i); }
	for (i = 0; i < 64; i++) hs[i] = (unsigned char)i;

	ssl3_prf(pm, 48, cr, 32, sr, 32, master, 48);
	ssl3_prf(master, 48, sr, 32, cr, 32, kb, 136);
	ssl3_finished(master, hs, 64, (const unsigned char[]){0x54,0x4e,0x4c,0x43}, fin);

	memcpy(c.cmac, kb + 0, 20); memcpy(c.smac, kb + 20, 20);
	memcpy(c.ckey, kb + 40, 32); memcpy(c.skey, kb + 72, 32);
	memcpy(c.civ, kb + 104, 16); memcpy(c.siv, kb + 120, 16);
	c.send_seq = c.recv_seq = 0;
	fin_hs[0] = 0x14; fin_hs[1] = 0; fin_hs[2] = 0; fin_hs[3] = 0x24;
	memcpy(fin_hs + 4, fin, 36);
	rl = seal_record(&c, 0x16, fin_hs, 40, rec);

	printf("master=");
	for (i = 0; i < 48; i++) printf("%02x", master[i]);
	printf("\nkeyblock=");
	for (i = 0; i < 136; i++) printf("%02x", kb[i]);
	printf("\nfinished=");
	for (i = 0; i < 36; i++) printf("%02x", fin[i]);
	printf("\nrecord=");
	for (i = 0; i < rl; i++) printf("%02x", rec[i]);
	printf("\n");
}

static void rsa_selftest(const char *path)
{
	int len = 0, i, le;
	unsigned char *m = read_file(path, &len);
	unsigned char msg[48], out[512];

	if (!m || len != MODLEN) {
		fprintf(stderr, "rsatest needs a %d-byte modulus\n", MODLEN);
		return;
	}
	for (i = 0; i < 48; i++) msg[i] = (unsigned char)i;
	msg[0] = 0x03; msg[1] = 0x00;
	for (le = 1; le >= 0; le--) {
		if (rsa_pkcs1_encrypt(m, len, le, msg, 48, out) < 0) {
			printf("le=%d failed\n", le);
			continue;
		}
		printf("rsa le=%d c=", le);
		for (i = 0; i < len; i++) printf("%02x", out[i]);
		printf("\n");
	}
	free(m);
}

static void cv_selftest(void)
{
	static const unsigned char trans[] = "VFS491 handshake transcript";
	unsigned char ownmod[MODLEN], dig[36], sig[512], chk[512];
	unsigned int sl = 0;
	unsigned i;
	RSA *r;

	md5_sha1(trans, (int)sizeof(trans) - 1, dig);
	printf("md5_sha1(transcript) = ");
	for (i = 0; i < 36; i++)
		printf("%02x", dig[i]);
	printf("\n");

	r = gen_rsa(ownmod, MODLEN);
	if (!r) {
		printf("gen_rsa: FAIL\n");
		return;
	}
	printf("gen_rsa modulus[0..3] = %02x%02x%02x%02x\n",
	       ownmod[0], ownmod[1], ownmod[2], ownmod[3]);

	if (RSA_sign(NID_md5_sha1, dig, 36, sig, &sl, r) != 1) {
		printf("RSA_sign(md5_sha1): FAIL\n");
		RSA_free(r);
		return;
	}
	printf("RSA_sign ok (%u bytes)\n", sl);

	/* Standard (big-endian) signature must verify as produced. */
	if (RSA_verify(NID_md5_sha1, dig, 36, sig, sl, r) != 1) {
		printf("RSA_verify(as-is): FAIL\n");
		RSA_free(r);
		return;
	}
	printf("RSA_verify(as-is, big-endian wire form): ok\n");

	/* --cv-rev sends the byte-reversed body; it must NOT verify. */
	memcpy(chk, sig, sl);
	reverse_buf(chk, (int)sl);
	if (RSA_verify(NID_md5_sha1, dig, 36, chk, sl, r) != 1)
		printf("RSA_verify(byte-reversed): as expected, does not verify\n");

	RSA_free(r);
	printf("cv_selftest: PASS\n");
}

static void usage(const char *a)
{
	fprintf(stderr,
		"usage: %s P1 P2 --pubkey MOD.bin [options]\n"
		"\n"
		"  P1 P2              the two 0x06 patch payload files (vendor IP, you supply)\n"
		"  --pubkey FILE      client cert RSA-2048 modulus (DataID 0xc, flash 0x15b6)\n"
		"  --cke-key FILE     server RSA-2048 modulus used to encrypt the CKE (DataID 0xa, flash 0x16b6)\n"
		"  --modle | --modbe  modulus byte order (default: le, as in reference/vfs495-linux)\n"
		"  --cke-modle | --cke-modbe  byte order for --cke-key (default: follows --modle)\n"
		"  --cv FILE          CertificateVerify(0x0f) body bytes (256)\n"
		"  --cv-zeros         send a zero 0x0f body (default)\n"
		"  --cv-premaster     make the 0x0f an RSA encryption of the premaster\n"
		"  --cv-rsa           make the 0x0f a well-formed RSA block, random content\n"
		"  --cv-key FILE      sign the 0x0f exactly as the vendor does: master-keyed\n"
		"                     SSLv3 hash (empty sender label), raw PKCS#1, with the\n"
		"                     client private key from the decrypted DataID 0x0d blob\n"
		"  --own-key          present a fresh client key and sign the 0x0f with it\n"
		"  --cv-rev           byte-reverse the signed 0x0f body (as the vendor does)\n"
		"  --no-cert          omit the Certificate message\n"
		"  --no-cv            omit the CertificateVerify message\n"
		"  --no-spi           skip the two 0x1f flash reads\n"
		"  --spi-dump PREFIX  save the two 0x1f reads to PREFIX1.bin / PREFIX2.bin\n"
		"  --app              after the handshake, send an encrypted GET_VERSION\n"
		"  --cmd HEX          send this VCSFW command (hex bytes) as encrypted AppData\n"
		"  --image            after --cmd, read plaintext frames from EP 0x82\n"
		"  --image-out FILE   save the raw EP 0x82 stream to FILE\n"
		"\n"
		"Unlocks and completes the SSLv3 handshake.  Patches land in sensor RAM only.\n", a);
}

int main(int argc, char **argv)
{
	const char *p1 = NULL, *p2 = NULL, *pk = NULL, *cvf = NULL, *ckek = NULL;
	const char *cvkeyf = NULL;
	const char *signrawf = NULL;
	struct hs_opt o = { .modle = 1, .cv = NULL, .have_cert = 1, .have_cv = 1,
			    .do_app = 0, .ckemod = NULL, .ckemodle = 1 };
	int spi = 1, i, modlen = 0, order_forced = 0, r, best = 0, ckeforce = -1;
	unsigned char *mod = NULL;
	unsigned char *cvbuf = NULL;
	unsigned char *ckebuf = NULL;
	libusb_device **list = NULL;
	libusb_device *found = NULL;
	libusb_device_handle *handle = NULL;
	ssize_t nd;

	for (i = 1; i < argc; i++)
		if (!strcmp(argv[i], "--selftest")) {
			selftest();
			return 0;
		} else if (!strcmp(argv[i], "--rsatest") && i + 1 < argc) {
			rsa_selftest(argv[++i]);
			return 0;
		} else if (!strcmp(argv[i], "--cvselftest")) {
			cv_selftest();
			return 0;
		}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--pubkey") && i + 1 < argc)
			pk = argv[++i];
		else if (!strcmp(argv[i], "--cv") && i + 1 < argc) {
			cvf = argv[++i];
			o.cv_mode = 1;
		} else if (!strcmp(argv[i], "--cv-zeros")) {
			cvf = NULL;
			o.cv_mode = 0;
		} else if (!strcmp(argv[i], "--cv-premaster"))
			o.cv_mode = 2;
		else if (!strcmp(argv[i], "--cv-rsa"))
			o.cv_mode = 3;
		else if (!strcmp(argv[i], "--own-key"))
			o.cv_mode = 4;
		else if (!strcmp(argv[i], "--cv-key") && i + 1 < argc) {
			cvkeyf = argv[++i];
			o.cv_mode = 5;
		}
		else if (!strcmp(argv[i], "--signraw") && i + 1 < argc)
			signrawf = argv[++i];
		else if (!strcmp(argv[i], "--cv-rev"))
			o.cv_rev = 1;
		else if (!strcmp(argv[i], "--modle")) {
			o.modle = 1;
			order_forced = 1;
		} else if (!strcmp(argv[i], "--modbe")) {
			o.modle = 0;
			order_forced = 1;
		}
		else if (!strcmp(argv[i], "--cke-key") && i + 1 < argc)
			ckek = argv[++i];
		else if (!strcmp(argv[i], "--cke-modle"))
			ckeforce = 1;
		else if (!strcmp(argv[i], "--cke-modbe"))
			ckeforce = 0;
		else if (!strcmp(argv[i], "--no-cert"))
			o.have_cert = 0;
		else if (!strcmp(argv[i], "--no-cv"))
			o.have_cv = 0;
		else if (!strcmp(argv[i], "--no-spi"))
			spi = 0;
		else if (!strcmp(argv[i], "--spi-dump") && i + 1 < argc)
			g_spi_dump = argv[++i];
		else if (!strcmp(argv[i], "--app"))
			o.do_app = 1;
		else if (!strcmp(argv[i], "--cmd") && i + 1 < argc)
			o.app_hex = argv[++i];
		else if (!strcmp(argv[i], "--image"))
			o.do_image = 1;
		else if (!strcmp(argv[i], "--image-out") && i + 1 < argc)
			o.image_out = argv[++i];
		else if (argv[i][0] == '-') {
			usage(argv[0]);
			return 2;
		} else if (!p1)
			p1 = argv[i];
		else if (!p2)
			p2 = argv[i];
		else {
			usage(argv[0]);
			return 2;
		}
	}
	if (signrawf) {
		/* Offline: sign a 36-byte digest with --cv-key exactly as the
		 * handshake does (raw PKCS#1, big-endian) and print it.  Used to
		 * confirm the path against a vendor-captured CertificateVerify. */
		RSA *k;
		unsigned char *dg, sig[512];
		int dl = 0, sl;

		if (!cvkeyf) {
			fprintf(stderr, "--signraw needs --cv-key\n");
			return 2;
		}
		k = load_cv_key(cvkeyf);
		dg = read_file(signrawf, &dl);
		if (!k || !dg) {
			fprintf(stderr, "--signraw: cannot load key or digest\n");
			return 2;
		}
		printf("key: %d-bit, self-check %s\n", RSA_bits(k),
		       RSA_check_key(k) == 1 ? "ok" : "FAILED");
		sl = raw_pkcs1_sign(k, dg, dl, sig);
		if (sl < 0) {
			fprintf(stderr, "--signraw: signing failed\n");
			return 2;
		}
		for (int j = 0; j < sl; j++)
			printf("%02x", sig[j]);
		printf("\n");
		return 0;
	}
	if (!p1 || !p2 || !pk) {
		usage(argv[0]);
		return 2;
	}

	mod = read_file(pk, &modlen);
	if (!mod || modlen != MODLEN) {
		fprintf(stderr, "pubkey must be %d bytes (got %d)\n", MODLEN, modlen);
		return 2;
	}
	if (cvkeyf) {
		o.cvkey = load_cv_key(cvkeyf);
		if (!o.cvkey) {
			fprintf(stderr, "--cv-key: cannot load an RSA key from %s\n",
				cvkeyf);
			return 2;
		}
		printf("CV key   (client, DataID 0x0d): %s (%d-bit)\n",
		       cvkeyf, RSA_bits(o.cvkey));
	}
	if (ckek) {
		int cl = 0;
		ckebuf = read_file(ckek, &cl);
		if (!ckebuf || cl != MODLEN) {
			fprintf(stderr, "--cke-key must be %d bytes (got %d)\n",
				MODLEN, cl);
			return 2;
		}
		o.ckemod = ckebuf;
		printf("CKE key  (server, DataID 0xa): %s\n", ckek);
		printf("cert key (client, DataID 0xc): %s\n", pk);
	}
	if (cvf) {
		int cl = 0;
		cvbuf = read_file(cvf, &cl);
		if (!cvbuf || cl != 256) {
			fprintf(stderr, "--cv file must be 256 bytes\n");
			return 2;
		}
		o.cv = cvbuf;
	}

	if (libusb_init(NULL) < 0) {
		fprintf(stderr, "libusb_init failed\n");
		return 2;
	}
	nd = libusb_get_device_list(NULL, &list);
	for (ssize_t k = 0; k < nd; k++) {
		struct libusb_device_descriptor dd;
		if (libusb_get_device_descriptor(list[k], &dd) < 0)
			continue;
		if (dd.idVendor == VID && dd.idProduct == PID) {
			found = list[k];
			break;
		}
	}
	if (!found) {
		fprintf(stderr, "VFS491 (138a:003d) not found\n");
		goto out;
	}
	if (libusb_open(found, &handle) < 0) {
		fprintf(stderr, "cannot open the device\n");
		goto out;
	}
#if LIBUSB_API_VERSION >= 0x01000102
	libusb_set_auto_detach_kernel_driver(handle, 1);
#endif
	if (libusb_claim_interface(handle, 0) < 0) {
		fprintf(stderr, "cannot claim interface 0\n");
		goto close;
	}
	libusb_set_interface_alt_setting(handle, 0, 0);
	drain(handle);

	printf("VFS491 at bus %u device %u\n\n", libusb_get_bus_number(found),
	       libusb_get_device_address(found));

	printf("== unlock ==\n");
	unlock(handle, p1, p2, spi);

	/* The sensor modulus byte order is device/firmware specific: the VFS495
	 * work found little-endian, but confirm on hardware.  Unless the caller
	 * pinned an order, try little-endian then big-endian in one run. */
	{
		int orders[2], no = 0, k;
		if (order_forced) {
			orders[no++] = o.modle;
		} else {
			/* Single attempt by default: a rejected handshake makes the
			 * sensor re-enumerate, so a second attempt in the same
			 * process can only ever fail.  Run with --modbe for the
			 * other modulus byte order. */
			orders[no++] = 1;
		}
		for (k = 0; k < no; k++) {
			if (k > 0) {
				reset_pipe(handle);
				usleep(200 * 1000);
			}
			o.modle = orders[k];
			o.ckemodle = (ckeforce < 0) ? o.modle : ckeforce;
			printf("\n== SSLv3 handshake (modulus %s-endian) ==\n",
			       o.modle ? "little" : "big");
			r = handshake(handle, mod, modlen, &o);
			if (r > best)
				best = r;
			if (r == 1)
				break;
		}
		printf("\n== result: %s ==\n",
		       best == 1 ? "handshake COMPLETE (keys agree)"
				 : "handshake not completed - see the trace above");
		if (best != 1 && !order_forced)
			printf("   (retry with --modbe, in a fresh run, for the other modulus byte order)\n");
	}

	libusb_release_interface(handle, 0);
close:
	libusb_close(handle);
out:
	free(mod);
	free(cvbuf);
	free(ckebuf);
	if (o.cvkey)
		RSA_free(o.cvkey);
	libusb_free_device_list(list, 1);
	libusb_exit(NULL);
	return 0;
}
