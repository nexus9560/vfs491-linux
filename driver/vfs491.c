/*
 * vfs491.c -- libfprint driver for the Validity Sensors VFS491
 *             (USB 138a:003d, HP EliteBook 8770w and friends).
 *
 * Copyright (C) 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * ---------------------------------------------------------------------
 * The VFS491 is a Falcon-family swipe sensor.  Its command set (VCSFW)
 * is plaintext on bulk EP 0x01/0x81, but every interesting operation
 * (capture configuration, ...) runs *inside* a proprietary SSLv3
 * session on command 0x11.  The sensor refuses to open that session
 * until two HP firmware "patches" (VCSFW 0x06) are uploaded into its
 * RAM, and it authenticates the client with a device-provisioned
 * RSA-2048 keypair stored in its SPI flash.
 *
 * The protocol was reverse-engineered in the `fingerprint-sensor`
 * repository (docs/protocol.md, docs/ssl-notes.md there).  Summary:
 *
 *   unlock:   GET_VERSION(0x01), GET_START_INFO(0x19),
 *             DOWNLOAD_PATCH(0x06, patch1), DOWNLOAD_PATCH(0x06, patch2)
 *             -> GET_VERSION shows patch flag 0x07, tunnel un-gated
 *   session:  ClientHello (suites 0x0044/0x0043/0x0042) tunneled as
 *             0x11 <u16le len> <TLS record>; the sensor answers with a
 *             raw TLS ServerHello + CertificateRequest +
 *             ServerHelloDone flight on EP 0x81.  The client answers
 *             with Certificate (client key modulus, storage DataID
 *             0x0c) + ClientKeyExchange (RSA premaster, encrypted to
 *             the *server* key DataID 0x0a) + CertificateVerify
 *             (0x0f: an SSLv3-Finished-style digest keyed by the
 *             master secret, raw-PKCS#1-signed with the client
 *             *private* key, storage DataID 0x0d) + CCS + Finished,
 *             all in one 0x11 tunnel.  Cipher suite 0x0044 =
 *             AES-256-CBC-SHA1 with a Validity record-MAC variant
 *             that omits the length field.
 *   capture:  the capture configuration is sent as encrypted AppData
 *             (raw 0x17 TLS records on EP 0x01 / 0x81); scan lines
 *             come back in the clear on EP 0x82 as 288-byte records:
 *             an 8-byte header (01 fe <ctr> 00 08 08 18 00), 264
 *             descrambled pixels, 16 bytes of aux data.
 *
 * The two patch blobs and the decrypted client key blob are HP's
 * proprietary firmware/IP.  This driver embeds none of it: it loads
 * the files at runtime from /usr/libexec/vfs491/ (override with
 * FP_VFS491_DIR).  Everything else -- crypto, handshake, line decode,
 * image assembly -- is implemented here in open code.
 */

#define FP_COMPONENT "vfs491"

/* The driver uses a few OpenSSL 1.1 RSA convenience APIs that are
 * deprecated-but-functional in OpenSSL 3.x (same pattern as the
 * reference tooling).  Suppress the deprecation noise locally. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "drivers_api.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <string.h>
#include <math.h>

/* ------------------------------------------------------------------ proto */

#define VFS491_USB_VENDOR  0x138a
#define VFS491_USB_PRODUCT 0x003d

#define VFS491_EP_CMD_OUT   0x01
#define VFS491_EP_CMD_IN    0x81
#define VFS491_EP_IMAGE_IN  0x82

#define VFS491_CMD_GET_VERSION     0x01
#define VFS491_CMD_GET_CONFIG      0x02
#define VFS491_CMD_DOWNLOAD_PATCH  0x06
#define VFS491_CMD_SSL_TUNNEL      0x11
#define VFS491_CMD_GET_START_INFO  0x19

#define VFS491_CMD_TIMEOUT_MS   2000
#define VFS491_READ_TIMEOUT_MS  1500
#define VFS491_READ_SIZE        8192
#define VFS491_STAGE_SIZE       (VFS491_LINE_SIZE + VFS491_READ_SIZE)

#define VFS491_MODLEN           256     /* RSA-2048 */
#define VFS491_LINE_SIZE        288     /* 8 hdr + 264 px + 16 trailer */
#define VFS491_LINE_HDR         8
#define VFS491_LINE_WIDTH       264     /* descrambled pixels per line */
#define VFS491_IMAGE_WIDTH      200     /* usable main-image columns   */

#define VFS491_MIN_LINES        100     /* fewer good lines -> not a swipe */
#define VFS491_MAX_LINES        2400    /* hard cap per capture           */
#define VFS491_STATIC_WINDOW    100     /* lines back for motion check    */
#define VFS491_STATIC_MAD       18      /* mean-abs-diff below => static  */
#define VFS491_STATIC_LINES     30      /* sustained static lines => done */
#define VFS491_EMPTY_VAR        600     /* per-line SSD below => no finger */
#define VFS491_EMPTY_STOP       60      /* consecutive empties => swipe over */
#define VFS491_OFF_LINES        10      /* empty run => finger lifted */
#define VFS491_OUT_HEIGHT       600     /* assembled image target height */

/* Default vendor-blob directory; override with FP_VFS491_DIR. */
#define VFS491_VENDOR_DIR       "/usr/libexec/vfs491"

#include "vfs491_descramble.inc"

/* The capture configuration, recovered from the vendor session (the
 * minimal register table; the vendor's own command is 2331 bytes of
 * register writes -- this 17-byte subset captures fine). */
static const guint8 vfs491_capture_cmd[17] = {
  VFS491_CMD_GET_CONFIG, 0x20, 0x01, 0xff, 0x03, 0x15, 0x00, 0x08,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x28, 0x00, 0x00,
};

/* Runtime-tunable capture heuristics.  Defaults are calibrated against a
 * real capture (1022 lines): a static finger gives a per-line squared
 * deviation of 200-310 (200 main columns) and a mean-abs-diff of 5-10
 * between lines 100 apart, so a threshold comfortably above that marks a
 * lifted/still finger while a moving finger is far above it.  Override
 * with the matching FP_VFS491_* environment variable when tuning on new
 * hardware.  FP_VFS491_DUMP=<path.pgm> keeps every assembled image and
 * FP_VFS491_RAW=<path.raw> keeps the pre-assembly rows, both numbered by
 * action (enroll/verify/...) for offline inspection and replay. */
static int vfs491_tun_min_lines = VFS491_MIN_LINES;
static int vfs491_tun_max_lines = VFS491_MAX_LINES;
static int vfs491_tun_static_mad = VFS491_STATIC_MAD;
static int vfs491_tun_static_lines = VFS491_STATIC_LINES;
static int vfs491_tun_empty_var = VFS491_EMPTY_VAR;
static int vfs491_tun_empty_stop = VFS491_EMPTY_STOP;
static const char *vfs491_tun_dump = NULL;
static const char *vfs491_tun_trace = NULL;   /* per-line metric trace file  */
static const char *vfs491_tun_hdrcensus = NULL; /* frame-header census file */
static const char *vfs491_tun_wire = NULL;   /* raw EP 0x82 wire dump        */
static gboolean vfs491_tun_loaded = FALSE;

static void
vfs491_load_tunables (void)
{
  if (vfs491_tun_loaded)
    return;
  vfs491_tun_loaded = TRUE;

#define TUNE_INT(name, var)                                             \
  do {                                                                  \
    const char *e = g_getenv ("FP_VFS491_" name);                       \
    if (e && *e) { int v = atoi (e); if (v > 0) var = v; }              \
  } while (0)

  TUNE_INT ("MIN_LINES", vfs491_tun_min_lines);
  TUNE_INT ("MAX_LINES", vfs491_tun_max_lines);
  TUNE_INT ("STATIC_MAD", vfs491_tun_static_mad);
  TUNE_INT ("STATIC_LINES", vfs491_tun_static_lines);
  TUNE_INT ("EMPTY_VAR", vfs491_tun_empty_var);
  TUNE_INT ("EMPTY_STOP", vfs491_tun_empty_stop);
#undef TUNE_INT
  vfs491_tun_dump = g_getenv ("FP_VFS491_DUMP");
  vfs491_tun_trace = g_getenv ("FP_VFS491_TRACE");
  vfs491_tun_hdrcensus = g_getenv ("FP_VFS491_HDRCENSUS");
  vfs491_tun_wire = g_getenv ("FP_VFS491_WIRE");

  fp_dbg ("tunables: min_lines=%d max_lines=%d static_mad=%d "
          "static_lines=%d empty_var=%d empty_stop=%d",
          vfs491_tun_min_lines, vfs491_tun_max_lines, vfs491_tun_static_mad,
          vfs491_tun_static_lines, vfs491_tun_empty_var, vfs491_tun_empty_stop);
}

/* ------------------------------------------------------------------ crypto
 *
 * Ported verbatim (modulo naming) from the byte-exact-validated open
 * client in the fingerprint-sensor repo (tools/vfs491_ssl.c, whose
 * crypto self-tests cross-check an independent Python implementation
 * of the same spec). */

static void
vfs491_digest (const EVP_MD *md, const guint8 *in, int inlen, guint8 *out, guint *outlen)
{
  EVP_MD_CTX *c = EVP_MD_CTX_new ();

  EVP_DigestInit_ex (c, md, NULL);
  EVP_DigestUpdate (c, in, (size_t) inlen);
  EVP_DigestFinal_ex (c, out, outlen);
  EVP_MD_CTX_free (c);
}

/* SSLv3 PRF: MD5(secret || SHA1(salt || secret || seedA || seedB)) with
 * salt = (i+1) repetitions of 0x41+i, concatenated until n bytes. */
static void
vfs491_ssl3_prf (const guint8 *secret, int slen,
                 const guint8 *seedA, int alen,
                 const guint8 *seedB, int blen,
                 guint8 *out, int n)
{
  guint8 buf[1024];
  int done = 0, i = 0;

  while (done < n)
    {
      guint8 salt[64];
      int saltlen = i + 1;
      guint8 sh[20], md[16];
      guint shl, mdl;
      int bl = 0, take;

      memset (salt, 0x41 + i, (size_t) saltlen);
      memcpy (buf + bl, salt, (size_t) saltlen); bl += saltlen;
      memcpy (buf + bl, secret, (size_t) slen);  bl += slen;
      memcpy (buf + bl, seedA, (size_t) alen);   bl += alen;
      memcpy (buf + bl, seedB, (size_t) blen);   bl += blen;
      vfs491_digest (EVP_sha1 (), buf, bl, sh, &shl);

      memcpy (buf, secret, (size_t) slen);
      memcpy (buf + slen, sh, 20);
      vfs491_digest (EVP_md5 (), buf, slen + 20, md, &mdl);

      take = MIN (n - done, 16);
      memcpy (out + done, md, (size_t) take);
      done += take;
      i++;
    }
}

/* SSLv3 Finished: MD5^16 || SHA1^20 over
 *   transcript || [label] || master || 0x36 pad
 * outer-hashed with the master and 0x5c pad.  `label` may be NULL /
 * len 0: the sensor's CertificateVerify runs this exact construction
 * with no sender label.  The client/server labels are the raw
 * little-endian int bytes (CLNT -> 54 4e 4c 43). */
static void
vfs491_ssl3_finished (const guint8 *master,     /* 48 bytes */
                      const guint8 *hs, int hslen,
                      const guint8 *label, int labellen,
                      guint8 out[36])
{
  guint8 buf[1024];
  guint8 p1[48], p2[48], inner[20], d[20];
  guint il, dl;
  int bl;

  memset (p1, 0x36, 48);
  memset (p2, 0x5c, 48);
  bl = 0;
  memcpy (buf + bl, hs, (size_t) hslen); bl += hslen;
  if (labellen > 0) { memcpy (buf + bl, label, (size_t) labellen); bl += labellen; }
  memcpy (buf + bl, master, 48); bl += 48;
  memcpy (buf + bl, p1, 48); bl += 48;
  vfs491_digest (EVP_md5 (), buf, bl, inner, &il);
  memcpy (buf, master, 48);
  memcpy (buf + 48, p2, 48);
  memcpy (buf + 96, inner, 16);
  vfs491_digest (EVP_md5 (), buf, 48 + 48 + 16, d, &dl);
  memcpy (out, d, 16);

  memset (p1, 0x36, 40);
  memset (p2, 0x5c, 40);
  bl = 0;
  memcpy (buf + bl, hs, (size_t) hslen); bl += hslen;
  if (labellen > 0) { memcpy (buf + bl, label, (size_t) labellen); bl += labellen; }
  memcpy (buf + bl, master, 48); bl += 48;
  memcpy (buf + bl, p1, 40); bl += 40;
  vfs491_digest (EVP_sha1 (), buf, bl, inner, &il);
  memcpy (buf, master, 48);
  memcpy (buf + 48, p2, 40);
  memcpy (buf + 88, inner, 20);
  vfs491_digest (EVP_sha1 (), buf, 48 + 40 + 20, d, &dl);
  memcpy (out + 16, d, 20);
}

static int
vfs491_aes256cbc (int enc, const guint8 key[32], const guint8 iv[16],
                  const guint8 *in, int inlen, guint8 *out)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int n1 = 0, n2 = 0, ok;

  if (enc)
    ok = EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv);
  else
    ok = EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv);
  EVP_CIPHER_CTX_set_padding (ctx, 0);
  if (enc)
    ok &= EVP_EncryptUpdate (ctx, out, &n1, in, inlen);
  else
    ok &= EVP_DecryptUpdate (ctx, out, &n1, in, inlen);
  if (enc)
    ok &= EVP_EncryptFinal_ex (ctx, out + n1, &n2);
  else
    ok &= EVP_DecryptFinal_ex (ctx, out + n1, &n2);
  EVP_CIPHER_CTX_free (ctx);
  return ok ? n1 + n2 : -1;
}

struct vfs491_ssl_state
{
  guint8 cmac[20], smac[20];
  guint8 ckey[32], skey[32];
  guint8 civ[16],  siv[16];
  guint64 send_seq, recv_seq;
};

/* Validity SSLv3 record MAC variant: seq(8) || type(1) || data, no
 * length field (differs from stock TLS). */
static void
vfs491_rec_mac (const guint8 key[20], guint64 seq, guint8 type,
                const guint8 *data, int len, guint8 out[20])
{
  guint8 buf[1024];
  guint8 p1[40], p2[40], inner[20];
  guint il;
  int bl = 0;
  int i;

  memset (p1, 0x36, 40);
  memset (p2, 0x5c, 40);
  memcpy (buf + bl, key, 20); bl += 20;
  memcpy (buf + bl, p1, 40); bl += 40;
  for (i = 0; i < 8; i++)
    buf[bl++] = (guint8) (seq >> (56 - 8 * i));
  buf[bl++] = type;
  memcpy (buf + bl, data, (size_t) len); bl += len;
  vfs491_digest (EVP_sha1 (), buf, bl, inner, &il);

  bl = 0;
  memcpy (buf + bl, key, 20); bl += 20;
  memcpy (buf + bl, p2, 40); bl += 40;
  memcpy (buf + bl, inner, 20); bl += 20;
  vfs491_digest (EVP_sha1 (), buf, bl, out, &il);
}

/* Encrypt one record: 5-byte TLS header + AES-256-CBC ciphertext. */
static int
vfs491_seal_record (struct vfs491_ssl_state *c, guint8 type,
                    const guint8 *data, int len, guint8 *out)
{
  guint8 mac[20], body[1024], ct[1024];
  int bl, padlen, ctl;

  vfs491_rec_mac (c->cmac, c->send_seq, type, data, len, mac);
  c->send_seq++;

  memcpy (body, data, (size_t) len); bl = len;
  memcpy (body + bl, mac, 20); bl += 20;
  padlen = 16 - (bl % 16);
  memset (body + bl, padlen - 1, (size_t) padlen); bl += padlen;

  ctl = vfs491_aes256cbc (1, c->ckey, c->civ, body, bl, ct);
  if (ctl < 0)
    return -1;
  memcpy (c->civ, ct + ctl - 16, 16);

  out[0] = type; out[1] = 0x03; out[2] = 0x00;
  out[3] = (guint8) (ctl >> 8); out[4] = (guint8) ctl;
  memcpy (out + 5, ct, (size_t) ctl);
  return 5 + ctl;
}

/* Decrypt one record body; returns plaintext length or -1 (MAC fail). */
static int
vfs491_open_record (struct vfs491_ssl_state *c, guint8 type,
                    const guint8 *ct, int ctlen, guint8 *out)
{
  guint8 pt[1024], mac[20];
  int n = vfs491_aes256cbc (0, c->skey, c->siv, ct, ctlen, pt);
  int padlen, datalen;

  if (n < 0)
    return -1;
  padlen = pt[n - 1] + 1;
  datalen = n - 20 - padlen;
  if (datalen < 0 || datalen > n)
    return -1;
  vfs491_rec_mac (c->smac, c->recv_seq, type, pt, datalen, mac);
  c->recv_seq++;
  memcpy (c->siv, ct + ctlen - 16, 16);
  if (memcmp (mac, pt + datalen, 20) != 0)
    return -1;
  memcpy (out, pt, (size_t) datalen);
  return datalen;
}

/* Load the device-provisioned client RSA private key: the decrypted
 * DataID 0x0d storage blob (1184 bytes, every integer little-endian):
 *   n@0x14, p@0x114, q@0x194, dmp1@0x214, dmq1@0x294, iqmp@0x314, d@0x394. */
static RSA *
vfs491_load_cv_key (GBytes *blob)
{
  gsize len = 0;
  const guint8 *b = g_bytes_get_data (blob, &len);
  BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
  RSA *r;

  if (len < 0x494)
    return NULL;

  n    = BN_lebin2bn (b + 0x14,  0x100, NULL);
  p    = BN_lebin2bn (b + 0x114, 0x80,  NULL);
  q    = BN_lebin2bn (b + 0x194, 0x80,  NULL);
  dmp1 = BN_lebin2bn (b + 0x214, 0x80,  NULL);
  dmq1 = BN_lebin2bn (b + 0x294, 0x80,  NULL);
  iqmp = BN_lebin2bn (b + 0x314, 0x80,  NULL);
  d    = BN_lebin2bn (b + 0x394, 0x100, NULL);
  e    = BN_new ();
  r    = RSA_new ();

  if (!n || !p || !q || !dmp1 || !dmq1 || !iqmp || !d || !e || !r)
    return NULL;
  BN_set_word (e, RSA_F4);
  if (RSA_set0_key (r, n, e, d) != 1 ||
      RSA_set0_factors (r, p, q) != 1 ||
      RSA_set0_crt_params (r, dmp1, dmq1, iqmp) != 1)
    return NULL;
  return r;
}

/* Raw RSA PKCS#1 v1.5 signature over `dig` (type 1, no DigestInfo):
 * exactly what the sensor expects in the 0x0f CertificateVerify.
 * Output is standard big-endian (wire order). */
static int
vfs491_raw_pkcs1_sign (RSA *r, const guint8 *dig, int diglen, guint8 *out)
{
  int k = RSA_size (r);
  guint8 em[512];
  int i, padlen = k - 3 - diglen;

  if (k <= 3 + diglen || k > (int) sizeof (em))
    return -1;
  em[0] = 0x00;
  em[1] = 0x01;
  for (i = 0; i < padlen; i++)
    em[2 + i] = 0xff;
  em[2 + padlen] = 0x00;
  memcpy (em + 3 + padlen, dig, (size_t) diglen);
  return RSA_private_encrypt (k, em, out, r, RSA_NO_PADDING);
}

/* RSA PKCS#1 v1.5 type-2 encrypt a short message.  `le` selects whether
 * the stored modulus buffer is a little-endian integer (this device:
 * yes).  The wire ciphertext is big-endian. */
static int
vfs491_rsa_pkcs1_encrypt (const guint8 *mod, int modlen, int le,
                          const guint8 *msg, int msglen, guint8 *out)
{
  BIGNUM *n = le ? BN_lebin2bn (mod, modlen, NULL) : BN_bin2bn (mod, modlen, NULL);
  BIGNUM *e = BN_new ();
  BIGNUM *m = BN_new ();
  BIGNUM *c = BN_new ();
  BN_CTX *ctx = BN_CTX_new ();
  guint8 em[VFS491_MODLEN];
  guint8 ps[VFS491_MODLEN];
  int pslen = modlen - 3 - msglen, i, ret = -1;

  if (!n || !e || !m || !c || !ctx || pslen < 8 || pslen > VFS491_MODLEN)
    goto out;

  /* One read of /dev/urandom, not one per byte. */
  {
    GRand *r = g_rand_new ();
    for (i = 0; i < pslen; i++)
      ps[i] = (guint8) g_rand_int (r) & 0xff;
    g_rand_free (r);
  }

  em[0] = 0x00;
  em[1] = 0x02;
  for (i = 0; i < pslen; i++)
    em[2 + i] = ps[i] ? ps[i] : 0x01;      /* PKCS#1 PS != 0 */
  em[2 + pslen] = 0x00;
  memcpy (em + 3 + pslen, msg, (size_t) msglen);

  BN_set_word (e, RSA_F4);
  BN_bin2bn (em, modlen, m);
  if (!BN_mod_exp (c, m, e, n, ctx))
    goto out;
  if (BN_bn2binpad (c, out, modlen) != modlen)
    goto out;
  ret = 0;
out:
  BN_free (n); BN_free (e); BN_free (m); BN_free (c); BN_CTX_free (ctx);
  return ret;
}

/* ------------------------------------------------------------------ device */

struct _FpDeviceVfs491
{
  FpImageDevice parent;

  /* vendor blobs (runtime files; never embedded) */
  guint8      *patch1_cmd;      /* 0x06 || patch1 */
  gsize        patch1_len;
  guint8      *patch2_cmd;
  gsize        patch2_len;
  guint8       certmod[VFS491_MODLEN];   /* DataID 0x0c (Certificate)  */
  guint8       ckemod[VFS491_MODLEN];    /* DataID 0x0a (CKE server key) */
  RSA         *cvkey;                    /* DataID 0x0d (CV signer)    */

  /* SSL session */
  gboolean               session_up;
  struct vfs491_ssl_state ssl;

  /* capture state */
  guint8                *stage;          /* line-staging buffer        */
  gsize                  stage_len;
  guint8                *readbuf;        /* raw EP 0x82 transfer target */
  GSList                *rows;
  guint                  lines_recorded;
  guint                  lines_static;   /* sustained static-line count */
  guint                  empty_lines;
  gboolean               finish_requested; /* stop early; keep row count honest */
  guint8                 ref_row[VFS491_LINE_WIDTH];  /* motion reference   */
  guint8                 win_row[VFS491_STATIC_WINDOW][VFS491_LINE_WIDTH];
  guint                  win_pos;
  guint                  win_fill;
  gboolean               finger_reported;
  gboolean               awaiting_finger_off; /* image submitted, wait for lift */
  gboolean               finger_off_seen;     /* empty run while waiting      */

  /* per-line metric tracing (FP_VFS491_TRACE) */
  FILE                  *trace;
  guint8                 prev_trace_row[VFS491_LINE_WIDTH];
  gboolean               have_prev_trace_row;

  /* frame-header census (FP_VFS491_HDRCENSUS) */
  FILE                  *hdr;

  /* raw wire dump (FP_VFS491_WIRE) */
  FILE                  *wire;

  gboolean               loop_running;
  gboolean               deactivating;
  gboolean               activation_complete; /* activate_complete sent?     */

  /* open-time scratch */
  guint8                *rxbuf;          /* command-reply staging (open) */
};

G_DECLARE_FINAL_TYPE (FpDeviceVfs491, fpi_device_vfs491, FPI, DEVICE_VFS491,
                      FpImageDevice);
G_DEFINE_TYPE (FpDeviceVfs491, fpi_device_vfs491, FP_TYPE_IMAGE_DEVICE);

/* The sensor's RSA moduli are stored little-endian; this is remembered
 * per machine so a wrong guess on one open is corrected on the next. */
static gint vfs491_modulus_le = 1;

static void
vfs491_start_scan (FpImageDevice *dev);

/* ------------------------------------------------------------------ files */

static GBytes *
vfs491_load_file (const char *dir, const char *name, gsize expect, GError **error)
{
  char *path;
  gchar *data = NULL;
  gsize len = 0;
  GBytes *ret;

  path = g_build_filename (dir, name, NULL);
  if (!g_file_get_contents (path, &data, &len, error))
    {
      g_prefix_error (error, "cannot read vendor file ");
      g_free (path);
      return NULL;
    }
  g_free (path);
  if (expect && len != expect)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "vendor file %s has %zu bytes, expected %zu", name, len, expect);
      g_free (data);
      return NULL;
    }
  ret = g_bytes_new_take (data, len);
  return ret;
}

/* ------------------------------------------------------------------ usb */

/* Drain anything stale on an IN endpoint so a previous crashed session
 * does not stall the command pipe.  Uses short synchronous transfers;
 * safe at open time. */
static void
vfs491_drain_ep (FpDeviceVfs491 *self, guint8 ep)
{
  guint8 tmp[4096];
  int i;

  for (i = 0; i < 16; i++)
    {
      g_autoptr (FpiUsbTransfer) transfer = fpi_usb_transfer_new (FP_DEVICE (self));
      g_autoptr (GError) err = NULL;

      fpi_usb_transfer_fill_bulk_full (transfer, ep, tmp, sizeof (tmp), NULL);
      if (!fpi_usb_transfer_submit_sync (transfer, 50, &err) ||
          transfer->actual_length == 0)
        break;
    }
}

/* ------------------------- generic command exchange (open/unlock) -------- */

enum {
  ACTION_SEND,
  ACTION_RECEIVE,
};

struct vfs491_action {
  int             type;
  const char     *name;
  int             endpoint;
  int             size;
  const guint8   *data;
  gboolean        check_status;   /* verify u16 LE status == 0 */
};

struct vfs491_exchange_data {
  int                 stepcount;
  FpImageDevice      *device;
  struct vfs491_action *actions;
  guint8             *receive_buf;
  int                 receive_cap;
};

static void
vfs491_async_send_cb (FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  fpi_ssm_next_state (transfer->ssm);
}

static void
vfs491_async_recv_cb (FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer user_data, GError *error)
{
  struct vfs491_exchange_data *data = fpi_ssm_get_data (transfer->ssm);
  struct vfs491_action *action;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  action = &data->actions[fpi_ssm_get_cur_state (transfer->ssm)];

  if (action->check_status)
    {
      guint16 status = 0;

      if (transfer->actual_length < 2)
        {
          fp_err ("short status reply (%zu bytes) for %s",
                  (gsize) transfer->actual_length, action->name);
          fpi_ssm_mark_failed (transfer->ssm,
                               fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
          return;
        }
      status = transfer->buffer[0] | (transfer->buffer[1] << 8);
      if (status != 0)
        {
          fp_err ("%s failed: sensor status 0x%04x", action->name, status);
          fpi_ssm_mark_failed (transfer->ssm,
                               fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
          return;
        }
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
vfs491_exchange_loop (FpiSsm *ssm, FpDevice *_dev)
{
  struct vfs491_exchange_data *data = fpi_ssm_get_data (ssm);
  struct vfs491_action *action = &data->actions[fpi_ssm_get_cur_state (ssm)];
  FpiUsbTransfer *transfer;

  switch (action->type)
    {
    case ACTION_SEND:
      fp_dbg ("sending %s", action->name);
      transfer = fpi_usb_transfer_new (_dev);
      fpi_usb_transfer_fill_bulk_full (transfer, action->endpoint,
                                       (guint8 *) action->data, action->size, NULL);
      transfer->ssm = ssm;
      transfer->short_is_error = TRUE;
      fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                               vfs491_async_send_cb, NULL);
      break;

    case ACTION_RECEIVE:
      fp_dbg ("receiving %s", action->name);
      transfer = fpi_usb_transfer_new (_dev);
      fpi_usb_transfer_fill_bulk_full (transfer, action->endpoint,
                                       data->receive_buf, data->receive_cap, NULL);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                               vfs491_async_recv_cb, NULL);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vfs491_usb_exchange_async (FpiSsm *ssm, struct vfs491_exchange_data *data,
                           const char *name)
{
  FpiSsm *subsm = fpi_ssm_new_full (FP_DEVICE (data->device),
                                    vfs491_exchange_loop,
                                    data->stepcount, data->stepcount, name);

  /* The caller hands ownership of @data to the sub-SSM; it must stay
   * alive until the exchange finishes (the callbacks run asynchronously
   * after the caller's stack frame is gone). */
  fpi_ssm_set_data (subsm, data, g_free);
  fpi_ssm_start_subsm (ssm, subsm);
}

/* ------------------------------------------------------------------ open */

/* One-byte commands sent as single-byte bulk transfers (the sensor wants
 * the command byte alone, no register payload). */
static const guint8 vfs491_cmd_get_version[] = { VFS491_CMD_GET_VERSION };
static const guint8 vfs491_cmd_get_start_info[] = { VFS491_CMD_GET_START_INFO };

enum {
  OPEN_DRAIN,
  OPEN_UNLOCK,
  OPEN_CHECK,
  OPEN_NUM_STATES,
};

static void
vfs491_open_loop (FpiSsm *ssm, FpDevice *_dev)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (_dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_DRAIN:
      /* Flush anything a previous crashed/killed session left behind:
       * a stale bulk-IN read would otherwise be handed to the first
       * command of the unlock sequence. */
      vfs491_drain_ep (self, VFS491_EP_CMD_IN);
      vfs491_drain_ep (self, VFS491_EP_IMAGE_IN);
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_UNLOCK:
      {
        /* HP's scsFalconDeviceInit sequence, replayed in open code:
         * GET_VERSION, GET_START_INFO, patch #1, patch #2, GET_VERSION.
         * (The vendor also does two 0x1f flash reads between the patches;
         * they are not needed to open the tunnel -- measured.) */
        static struct vfs491_action unlock_actions[] = {
          { ACTION_SEND,     "GET_VERSION",   VFS491_EP_CMD_OUT, 1,
            vfs491_cmd_get_version, FALSE },
          { ACTION_RECEIVE,  "GET_VERSION reply", VFS491_EP_CMD_IN, 0, NULL, FALSE },
          { ACTION_SEND,     "GET_START_INFO", VFS491_EP_CMD_OUT, 1,
            vfs491_cmd_get_start_info, FALSE },
          { ACTION_RECEIVE,  "GET_START_INFO reply", VFS491_EP_CMD_IN, 0, NULL, FALSE },
          { ACTION_SEND,     "DOWNLOAD_PATCH #1", VFS491_EP_CMD_OUT, 0, NULL, FALSE },
          { ACTION_RECEIVE,  "DOWNLOAD_PATCH #1 reply", VFS491_EP_CMD_IN, 0, NULL, TRUE },
          { ACTION_SEND,     "DOWNLOAD_PATCH #2", VFS491_EP_CMD_OUT, 0, NULL, FALSE },
          { ACTION_RECEIVE,  "DOWNLOAD_PATCH #2 reply", VFS491_EP_CMD_IN, 0, NULL, TRUE },
          { ACTION_SEND,     "GET_VERSION (post-patch)", VFS491_EP_CMD_OUT, 1,
            vfs491_cmd_get_version, FALSE },
          { ACTION_RECEIVE,  "GET_VERSION reply", VFS491_EP_CMD_IN, 0, NULL, FALSE },
        };
        struct vfs491_exchange_data *data = g_new0 (struct vfs491_exchange_data, 1);

        data->stepcount = G_N_ELEMENTS (unlock_actions);
        data->device = dev;
        data->actions = unlock_actions;
        data->receive_buf = self->rxbuf;
        data->receive_cap = 512;

        unlock_actions[4].data = self->patch1_cmd;
        unlock_actions[4].size = (int) self->patch1_len;
        unlock_actions[6].data = self->patch2_cmd;
        unlock_actions[6].size = (int) self->patch2_len;

        vfs491_usb_exchange_async (ssm, data, "UNLOCK");
      }
      break;

    case OPEN_CHECK:
      {
        /* The final GET_VERSION reply (38 bytes): patch flag at offset 17
         * reads 0x07 once both RAM patches are in. */
        if (self->rxbuf[17] == 0)
          {
            fp_err ("patches did not load (patch flag 0x%02x) -- check the "
                    "vendor blobs in " VFS491_VENDOR_DIR, self->rxbuf[17]);
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
            return;
          }
        fp_dbg ("unlock complete, patch flag 0x%02x", self->rxbuf[17]);
        fpi_ssm_next_state (ssm);
      }
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vfs491_open_loop_complete (FpiSsm *ssm, FpDevice *_dev, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);

  fpi_image_device_open_complete (dev, error);
}

static void
vfs491_dev_open (FpImageDevice *dev)
{
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (dev);
  FpiSsm *ssm;
  GError *error = NULL;
  const char *dir;
  g_autoptr (GBytes) patch1 = NULL, patch2 = NULL, cvblob = NULL, certmod = NULL, ckemod = NULL;
  gsize plen;

  vfs491_load_tunables ();

  dir = g_getenv ("FP_VFS491_DIR");
  if (!dir || !*dir)
    dir = VFS491_VENDOR_DIR;

  /* Vendor IP stays outside the binary: load it at runtime. */
  patch1 = vfs491_load_file (dir, "patch1.bin", 0, &error);
  if (!patch1)
    goto fail;
  patch2 = vfs491_load_file (dir, "patch2.bin", 0, &error);
  if (!patch2)
    goto fail;
  certmod = vfs491_load_file (dir, "cert_key.bin", VFS491_MODLEN, &error);
  if (!certmod)
    goto fail;
  ckemod = vfs491_load_file (dir, "cke_key.bin", VFS491_MODLEN, &error);
  if (!ckemod)
    goto fail;
  cvblob = vfs491_load_file (dir, "slot0d_plain.bin", 0, &error);
  if (!cvblob)
    goto fail;

  self->cvkey = vfs491_load_cv_key (cvblob);
  if (!self->cvkey)
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "slot0d_plain.bin is not a valid decrypted DataID 0x0d key blob");
      goto fail;
    }

  plen = g_bytes_get_size (patch1);
  self->patch1_cmd = g_malloc (plen + 1);
  self->patch1_cmd[0] = VFS491_CMD_DOWNLOAD_PATCH;
  memcpy (self->patch1_cmd + 1, g_bytes_get_data (patch1, NULL), plen);
  self->patch1_len = plen + 1;

  plen = g_bytes_get_size (patch2);
  self->patch2_cmd = g_malloc (plen + 1);
  self->patch2_cmd[0] = VFS491_CMD_DOWNLOAD_PATCH;
  memcpy (self->patch2_cmd + 1, g_bytes_get_data (patch2, NULL), plen);
  self->patch2_len = plen + 1;

  memcpy (self->certmod, g_bytes_get_data (certmod, NULL), VFS491_MODLEN);
  memcpy (self->ckemod, g_bytes_get_data (ckemod, NULL), VFS491_MODLEN);

  self->rxbuf = g_malloc0 (512);
  self->stage = g_malloc (VFS491_STAGE_SIZE);
  self->readbuf = g_malloc (VFS491_READ_SIZE);
  self->session_up = FALSE;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                     0, 0, &error))
    goto fail;

  ssm = fpi_ssm_new (FP_DEVICE (dev), vfs491_open_loop, OPEN_NUM_STATES);
  fpi_ssm_start (ssm, vfs491_open_loop_complete);
  return;

fail:
  g_clear_pointer (&self->cvkey, RSA_free);
  g_clear_pointer (&self->patch1_cmd, g_free);
  g_clear_pointer (&self->patch2_cmd, g_free);
  g_clear_pointer (&self->rxbuf, g_free);
  g_clear_pointer (&self->stage, g_free);
  fpi_image_device_open_complete (dev, error);
}

static void
vfs491_dev_close (FpImageDevice *dev)
{
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (dev);
  g_autoptr (GError) error = NULL;

  self->session_up = FALSE;
  g_clear_pointer (&self->cvkey, RSA_free);
  g_clear_pointer (&self->patch1_cmd, g_free);
  g_clear_pointer (&self->patch2_cmd, g_free);
  g_clear_pointer (&self->rxbuf, g_free);
  g_clear_pointer (&self->stage, g_free);
  g_slist_free_full (g_steal_pointer (&self->rows), g_free);

  if (self->trace)
    {
      fclose (self->trace);
      self->trace = NULL;
      self->have_prev_trace_row = FALSE;
    }

  if (self->hdr)
    {
      fclose (self->hdr);
      self->hdr = NULL;
    }

  if (self->wire)
    {
      fclose (self->wire);
      self->wire = NULL;
    }

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                  0, 0, &error);

  fpi_image_device_close_complete (dev, error);
}

/* ------------------------------------------------------------------ lines */

static void
vfs491_capture_reset (FpDeviceVfs491 *self)
{
  g_slist_free_full (g_steal_pointer (&self->rows), g_free);
  self->lines_recorded = 0;
  self->lines_static = 0;
  self->empty_lines = 0;
  self->finish_requested = FALSE;
  self->awaiting_finger_off = FALSE;
  self->finger_off_seen = FALSE;
  self->win_pos = 0;
  self->win_fill = 0;
  self->stage_len = 0;
  if (self->trace)
    fflush (self->trace);
  if (self->hdr)
    fflush (self->hdr);
  if (self->wire)
    fflush (self->wire);
}

/* Decode the staged byte stream into rows.  Each line is
 * 01 fe <ctr> 00 08 08 18 00 || 264 pixels || 16 aux.  Lines may span
 * USB reads; garbage before the first marker is dropped. */
static void
vfs491_process_bytes (FpDeviceVfs491 *self, const guint8 *data, gsize len)
{
  gsize i = 0;

  /* Raw wire capture: dump the exact EP 0x82 stream so the frame framing can
   * be re-parsed offline under different header/length rules.
   * FP_VFS491_WIRE=<path>. */
  if (vfs491_tun_wire && *vfs491_tun_wire)
    {
      if (self->wire == NULL)
        self->wire = fopen (vfs491_tun_wire, "wb");
      if (self->wire && len)
        fwrite (data, 1, len, self->wire);
    }

  /* append into the staging buffer */
  memcpy (self->stage + self->stage_len, data, MIN (len,
                                                    (gsize) VFS491_STAGE_SIZE - self->stage_len));
  self->stage_len += MIN (len, (gsize) VFS491_STAGE_SIZE - self->stage_len);

  while (self->stage_len >= VFS491_LINE_SIZE)
    {
      const guint8 *line = self->stage;
      guint8 row[VFS491_LINE_WIDTH];
      guint j;
      gint var;
      const guint8 *win;

      /* Audit instrumentation: record the 8 bytes we are about to interpret
       * as a frame header, at every record boundary (whether accepted or
       * rejected).  FP_VFS491_HDRCENSUS=<path>.  The wire header is
       * 01 [01|fe] [seq:u16] [f4] [f5] [byte6] [00]; logging the raw values
       * shows the true population of frame types/lengths. */
      if (vfs491_tun_hdrcensus && *vfs491_tun_hdrcensus)
        {
          if (self->hdr == NULL)
            self->hdr = fopen (vfs491_tun_hdrcensus, "w");
          if (self->hdr)
            fprintf (self->hdr, "%02x %02x %02x %02x %02x %02x %02x %02x\n",
                     line[0], line[1], line[2], line[3],
                     line[4], line[5], line[6], line[7]);
        }

      if (!(line[0] == 0x01 && (line[1] == 0x01 || line[1] == 0xfe) &&
            line[4] == 0x08 && line[5] == 0x08 && line[6] == 0x18 &&
            line[7] == 0x00))
        {
          /* resync: drop one byte */
          memmove (self->stage, self->stage + 1, --self->stage_len);
          continue;
        }

      /* descramble: out[descramble[i]] = wire[i] */
      for (j = 0; j < VFS491_LINE_WIDTH; j++)
        row[vfs491_descramble[j]] = line[VFS491_LINE_HDR + j];

      memmove (self->stage, self->stage + VFS491_LINE_SIZE,
               self->stage_len -= VFS491_LINE_SIZE);

      var = fpi_std_sq_dev (row, VFS491_IMAGE_WIDTH);

      /* Diagnostic: log per-line SSD and row-to-row novelty so the finger
       * gate can be calibrated from a real swipe.  FP_VFS491_TRACE=<path>.
       * Writes CSV: seq,ssd,novelty,mad_vs_window. */
      if (vfs491_tun_trace && *vfs491_tun_trace)
        {
          gdouble nov = -1.0;
          gint mad = -1;

          if (self->trace == NULL)
            {
              self->trace = fopen (vfs491_tun_trace, "w");
              if (self->trace)
                fprintf (self->trace,
                         "# seq,ssd,novelty,mad_vs_window,recorded\n");
            }

          if (self->have_prev_trace_row)
            {
              gint64 dot = 0, na = 0, nb = 0;
              for (j = 0; j < VFS491_IMAGE_WIDTH; j++)
                {
                  gint a = (gint) row[j] - 128;
                  gint b = (gint) self->prev_trace_row[j] - 128;
                  dot += (gint64) a * b;
                  na += (gint64) a * a;
                  nb += (gint64) b * b;
                }
              if (na > 0 && nb > 0)
                nov = 1.0 - (gdouble) dot / sqrt ((gdouble) na * (gdouble) nb);
            }

          if (self->win_fill >= VFS491_STATIC_WINDOW)
            {
              gint m = 0;
              const guint8 *w = self->win_row[self->win_pos];
              for (j = 0; j < VFS491_IMAGE_WIDTH; j++)
                m += ABS ((int) row[j] - (int) w[j]);
              mad = m / VFS491_IMAGE_WIDTH;
            }

          if (self->trace)
            fprintf (self->trace, "%u,%d,%.4f,%d,%d\n",
                     self->lines_recorded, var, nov, mad,
                     var >= vfs491_tun_empty_var);

          memcpy (self->prev_trace_row, row, VFS491_LINE_WIDTH);
          self->have_prev_trace_row = TRUE;
        }

      /* After handing an image to libfprint, wait until the finger is
       * lifted before starting a new capture.  Otherwise the static tail
       * of one swipe is submitted as several additional images. */
      if (self->awaiting_finger_off)
        {
          if (var < vfs491_tun_empty_var)
            {
              if (++self->empty_lines >= VFS491_OFF_LINES)
                self->finger_off_seen = TRUE;
            }
          else
            {
              self->empty_lines = 0;
            }
          continue;
        }

      if (var < vfs491_tun_empty_var)
        {
          /* no finger under the sensor: constant line */
          if (self->lines_recorded >= vfs491_tun_min_lines &&
              ++self->empty_lines >= vfs491_tun_empty_stop)
            self->finish_requested = TRUE;
          continue;
        }
      self->empty_lines = 0;

      /* motion detection: compare against the line VFS491_STATIC_WINDOW
       * good-lines back.  Static (finger lifted / resting) content has a
       * mean abs difference of ~8-9 on this sensor; a moving swipe is
       * several times that. */
      if (self->win_fill >= VFS491_STATIC_WINDOW)
        {
          win = self->win_row[self->win_pos];
          i = 0;
          for (j = 0; j < VFS491_IMAGE_WIDTH; j++)
            i += ABS ((int) row[j] - (int) win[j]);
          if (i / VFS491_IMAGE_WIDTH < vfs491_tun_static_mad)
            {
              if (++self->lines_static >= vfs491_tun_static_lines &&
                  self->lines_recorded >= vfs491_tun_min_lines)
                self->finish_requested = TRUE;
            }
          else
            {
              self->lines_static = 0;
            }
        }
      memcpy (self->win_row[self->win_pos], row, VFS491_LINE_WIDTH);
      self->win_pos = (self->win_pos + 1) % VFS491_STATIC_WINDOW;
      self->win_fill = MIN (self->win_fill + 1, VFS491_STATIC_WINDOW);

      self->rows = g_slist_prepend (self->rows, g_memdup2 (row, VFS491_LINE_WIDTH));
      self->lines_recorded++;
    }
}

/* ------------------------------------------------------------------ capture */

enum {
  ACTIVATE_ARM_SEND,
  ACTIVATE_ARM_RECV,
  ACTIVATE_READ,
  ACTIVATE_NUM_STATES,
};

/* Assembly pulls the usable main-image columns (0..IMAGE_WIDTH-1). */

static const char *
vfs491_action_name (FpDevice *dev)
{
  switch (fpi_device_get_current_action (dev))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      return "enroll";
    case FPI_DEVICE_ACTION_VERIFY:
      return "verify";
    case FPI_DEVICE_ACTION_IDENTIFY:
      return "identify";
    case FPI_DEVICE_ACTION_CAPTURE:
      return "capture";
    case FPI_DEVICE_ACTION_NONE:
    case FPI_DEVICE_ACTION_PROBE:
    case FPI_DEVICE_ACTION_OPEN:
    case FPI_DEVICE_ACTION_CLOSE:
    case FPI_DEVICE_ACTION_LIST:
    case FPI_DEVICE_ACTION_DELETE:
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
      break;
    }
  return "unknown";
}

static char *
vfs491_dump_path (const char *base, const char *action, guint seq,
                  const char *ext)
{
  g_autofree char *stem = g_strdup (base);
  char *dot = strrchr (stem, '.');

  if (dot)
    *dot = '\0';
  return g_strdup_printf ("%s-%s-%03u.%s", stem, action, seq, ext);
}

static void
vfs491_dump_capture (FpDevice *dev, FpImage *img, GSList *rows, guint nrows)
{
  static guint seq;
  const char *raw = g_getenv ("FP_VFS491_RAW");
  gboolean want_pgm = vfs491_tun_dump && *vfs491_tun_dump;
  gboolean want_raw = raw && *raw;
  const char *action;
  FILE *f;

  if (!want_pgm && !want_raw)
    return;

  action = vfs491_action_name (dev);
  seq++;

  if (want_pgm)
    {
      g_autofree char *path = vfs491_dump_path (vfs491_tun_dump, action,
                                                seq, "pgm");
      f = fopen (path, "wb");
      if (!f)
        {
          fp_warn ("could not write %s", path);
        }
      else
        {
          fprintf (f, "P5\n%u %u\n255\n", img->width, img->height);
          fwrite (img->data, 1, (size_t) img->width * img->height, f);
          fclose (f);
          fp_dbg ("wrote %s (%ux%u)", path, img->width, img->height);
        }
    }

  if (want_raw)
    {
      /* Pre-assembly rows, already descrambled.  The header allows the
       * offline replay tool to try other assembly settings. */
      g_autofree char *path = vfs491_dump_path (raw, action, seq, "raw");
      guint32 hdr[2];
      GSList *l;

      f = fopen (path, "wb");
      if (!f)
        {
          fp_warn ("could not write %s", path);
          return;
        }
      hdr[0] = GUINT32_TO_LE (VFS491_LINE_WIDTH);
      hdr[1] = GUINT32_TO_LE (nrows);
      fwrite ("VFS491RAW1", 1, 10, f);
      fwrite (hdr, sizeof (hdr), 1, f);
      for (l = rows; l; l = l->next)
        fwrite (l->data, 1, VFS491_LINE_WIDTH, f);
      fclose (f);
      fp_dbg ("wrote %s (%u rows)", path, nrows);

      if (vfs491_tun_trace && *vfs491_tun_trace)
        {
          g_autofree char *tp = vfs491_dump_path (raw, action, seq, "ssd");
          FILE *tf = fopen (tp, "w");
          if (tf)
            {
              for (l = rows; l; l = l->next)
                fprintf (tf, "%d\n",
                         fpi_std_sq_dev ((const guint8 *) l->data,
                                         VFS491_IMAGE_WIDTH));
              fclose (tf);
            }
        }
    }
}

/* Novelly-based assembling.
 *
 * libfprint's fpi_assemble_lines() infers finger speed from a local
 * overlap search (resolution / offset).  This sensor strongly oversamples
 * (adjacent rows correlate ~0.93, best-match offset is always 1), so that
 * estimate degenerates and the assembled image is stretched until the
 * ridge structure is smeared away.  Instead we mirror the known-good
 * offline reconstruction: remove the fixed per-column sensor pattern, use
 * the row-to-row novelty (1 - correlation) as a finger-displacement proxy,
 * and resample the captured lines onto a uniform displacement grid.  This
 * keeps the ridge pitch stable across swipes, which is what the minutiae
 * matcher needs.
 */
static FpImage *
vfs491_assemble_novelty (GSList *rows, guint nrows, guint width)
{
  guint8 *buf;
  gdouble *nov;
  gdouble *disp;
  guint8 *out;
  FpImage *img;
  guint i, x, n_out;
  gdouble total, med;
  gint *colsum;
  GSList *l;

  if (nrows < 2)
    return NULL;

  /* Copy rows into a flat buffer and remove the fixed per-column pattern
   * (sensor gain / optical noise), which carries most of the variance. */
  buf = g_malloc ((gsize) nrows * width);
  colsum = g_new0 (gint, width);
  for (l = rows, i = 0; l; l = l->next, i++)
    {
      const guint8 *r = l->data;
      for (x = 0; x < width; x++)
        {
          buf[(gsize) i * width + x] = r[x];
          colsum[x] += r[x];
        }
    }
  for (x = 0; x < width; x++)
    {
      gint mean = colsum[x] / (gint) nrows;
      for (i = 0; i < nrows; i++)
        {
          gint v = (gint) buf[(gsize) i * width + x] - mean + 128;
          buf[(gsize) i * width + x] = CLAMP (v, 0, 255);
        }
    }
  g_free (colsum);

  /* Novelty between consecutive lines: 1 - Pearson correlation.  Highly
   * oversampled rows give a small value; a moving finger gives more. */
  nov = g_new0 (gdouble, nrows);
  for (i = 1; i < nrows; i++)
    {
      const guint8 *a = buf + (gsize) (i - 1) * width;
      const guint8 *b = buf + (gsize) i * width;
      gint64 dot = 0, na = 0, nb = 0;
      for (x = 0; x < width; x++)
        {
          gint va = (gint) a[x] - 128;
          gint vb = (gint) b[x] - 128;
          dot += (gint64) va * vb;
          na += (gint64) va * va;
          nb += (gint64) vb * vb;
        }
      nov[i] = (na > 0 && nb > 0)
                 ? 1.0 - (gdouble) dot / sqrt ((gdouble) na * (gdouble) nb)
                 : 0.0;
    }

  /* Cumulative displacement proxy and its median positive step. */
  disp = g_new0 (gdouble, nrows);
  total = 0.0;
  for (i = 1; i < nrows; i++)
    {
      total += MAX (nov[i], 0.0);
      disp[i] = total;
    }

  med = 0.0;
  {
    guint cnt = 0;
    for (i = 1; i < nrows; i++)
      if (nov[i] > 0.0)
        {
          med += nov[i];
          cnt++;
        }
    if (cnt)
      med /= cnt;
  }
  if (total < 1e-6 || med < 1e-6)
    {
      g_free (buf);
      g_free (nov);
      g_free (disp);
      return NULL;
    }

  /* Resample onto a *fixed* output height.  The sensor's line rate and the
   * finger speed both vary between swipes, so the raw displacement total is
   * not comparable across swipes; normalising every capture to the same
   * height keeps the ridge pitch (and thus minutiae geometry) consistent,
   * which is what the matcher needs. */
  n_out = VFS491_OUT_HEIGHT;

  out = g_malloc ((gsize) width * n_out);
  for (i = 0; i < n_out; i++)
    {
      gdouble tgt = (n_out > 1) ? (total * i / (n_out - 1)) : 0.0;
      guint lo = 0, hi = nrows - 1;
      /* first index whose cumulative displacement reaches tgt */
      while (lo < hi)
        {
          guint mid = (lo + hi) / 2;
          if (disp[mid] < tgt)
            lo = mid + 1;
          else
            hi = mid;
        }
      memcpy (out + (gsize) i * width, buf + (gsize) lo * width, width);
    }

  g_free (buf);
  g_free (nov);
  g_free (disp);

  img = fp_image_new (width, n_out);
  img->width = width;
  img->height = n_out;
  img->flags = FPI_IMAGE_V_FLIPPED;
  memmove (img->data, out, (gsize) width * n_out);
  g_free (out);
  return img;
}

/* Tell libfprint the finger is gone.  Safe to call in any state: the
 * image-device helper ignores reports it cannot use. */
static void
vfs491_finish_finger_off (FpDeviceVfs491 *self, FpImageDevice *dev)
{
  if (self->finger_reported)
    {
      fpi_image_device_report_finger_status (dev, FALSE);
      self->finger_reported = FALSE;
    }
  self->awaiting_finger_off = FALSE;
  self->finger_off_seen = FALSE;
}

static void
vfs491_submit_image (FpDeviceVfs491 *self, FpImageDevice *dev)
{
  FpImage *img;
  FpiImageDeviceState state;

  if (self->lines_recorded < vfs491_tun_min_lines)
    {
      fp_dbg ("swipe too short (%u lines), retrying", self->lines_recorded);
      fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_SHORT);
      vfs491_capture_reset (self);
      self->awaiting_finger_off = TRUE;
      return;
    }

  /* Only hand over an image when libfprint expects one.  This races with
   * minutiae detection after the previous image; in that window the new
   * swipe is dropped and the user simply swipes again. */
  g_object_get (dev, "fpi-image-device-state", &state, NULL);
  if (state != FPI_IMAGE_DEVICE_STATE_CAPTURE)
    {
      fp_dbg ("not submitting image: image device state %d", state);
      vfs491_capture_reset (self);
      self->awaiting_finger_off = TRUE;
      return;
    }

  self->rows = g_slist_reverse (self->rows);
  img = vfs491_assemble_novelty (self->rows, self->lines_recorded,
                                 VFS491_IMAGE_WIDTH);
  if (img == NULL)
    {
      fp_dbg ("assembly produced no image, retrying");
      fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_SHORT);
      vfs491_capture_reset (self);
      self->awaiting_finger_off = TRUE;
      return;
    }
  vfs491_dump_capture (FP_DEVICE (dev), img, self->rows, self->lines_recorded);
  vfs491_capture_reset (self);

  fp_dbg ("image captured (%u x %u)", img->width, img->height);
  fpi_image_device_image_captured (dev, img);

  /* Do not report "finger off" yet.  For a swipe sensor the tail of the
   * same swipe is still streaming; wait for an empty run (or a read
   * timeout) before accepting the next capture. */
  self->awaiting_finger_off = TRUE;
}

static void
vfs491_capture_cb (FpiUsbTransfer *transfer, FpDevice *device,
                   gpointer user_data, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (device);
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (device);
  gboolean rearm = FALSE;

  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }

  if (error)
    {
      if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) ||
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
        {
          /* no data: the stream stopped, so the finger is gone. */
          g_clear_error (&error);
          if (self->awaiting_finger_off)
            {
              vfs491_finish_finger_off (self, dev);
              vfs491_capture_reset (self);
              rearm = TRUE;
            }
          else if (self->lines_recorded >= VFS491_MIN_LINES)
            {
              vfs491_submit_image (self, dev);
              vfs491_finish_finger_off (self, dev);
              vfs491_capture_reset (self);
              rearm = TRUE;
            }
          else if (self->finger_reported)
            {
              fp_dbg ("short swipe (%u lines), retrying",
                      self->lines_recorded);
              fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_SHORT);
              vfs491_finish_finger_off (self, dev);
              vfs491_capture_reset (self);
              rearm = TRUE;
            }
          fpi_ssm_jump_to_state (transfer->ssm,
                                 rearm ? ACTIVATE_ARM_SEND : ACTIVATE_READ);
          return;
        }
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length > 0)
    {
      if (self->awaiting_finger_off)
        {
          /* Still inspect lines: an empty run marks the finger as lifted. */
          vfs491_process_bytes (self, transfer->buffer, transfer->actual_length);
        }
      else
        {
          FpiImageDeviceState state;

          /* Only announce a finger when libfprint is actually waiting for
           * one; during minutiae detection the state is not ready yet. */
          if (!self->finger_reported)
            {
              g_object_get (dev, "fpi-image-device-state", &state, NULL);
              if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
                {
                  fpi_image_device_report_finger_status (dev, TRUE);
                  self->finger_reported = TRUE;
                }
            }

          if (self->finger_reported)
            vfs491_process_bytes (self, transfer->buffer,
                                  transfer->actual_length);
        }
    }

  /* An empty run after an image means the finger was lifted. */
  if (self->finger_off_seen)
    {
      vfs491_finish_finger_off (self, dev);
      vfs491_capture_reset (self);
      rearm = TRUE;
    }

  if (!self->awaiting_finger_off &&
      (self->finish_requested ||
       self->lines_recorded >= (guint) vfs491_tun_max_lines))
    vfs491_submit_image (self, dev);

  /* The sensor stops streaming after an image.  Arm the next capture as
   * soon as the finger is off, otherwise later swipes produce no data. */
  fpi_ssm_jump_to_state (transfer->ssm,
                         rearm ? ACTIVATE_ARM_SEND : ACTIVATE_READ);
}

static void
vfs491_arm_recv_cb (FpiUsbTransfer *transfer, FpDevice *device,
                    gpointer user_data, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (device);
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (device);
  guint8 plain[64];
  int pl;

  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length < 5 || transfer->buffer[0] != 0x17)
    {
      fp_err ("unexpected arm reply (%zu bytes, first 0x%02x)",
              (gsize) transfer->actual_length,
              transfer->actual_length ? transfer->buffer[0] : 0);
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  pl = vfs491_open_record (&self->ssl, 0x17, transfer->buffer + 5,
                           (transfer->buffer[3] << 8) | transfer->buffer[4], plain);
  if (pl < 2 || plain[0] != 0 || plain[1] != 0)
    {
      fp_err ("capture arm rejected (status %s)",
              pl >= 2 ? "non-zero" : "undecryptable");
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  vfs491_capture_reset (self);

  /* The first arm of this activation marks the device ready.  Without
   * this libfprint stays in ACTIVATING and rejects every image. */
  if (!self->activation_complete)
    {
      self->activation_complete = TRUE;
      fp_dbg ("capture armed, activation complete");
      fpi_image_device_activate_complete (dev, NULL);
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
vfs491_activate_loop (FpiSsm *ssm, FpDevice *_dev)
{
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (_dev);

  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_ARM_SEND:
      {
        /* The transfer owns the record buffer: it is read asynchronously
         * after this state has returned. */
        guint8 *rec = g_malloc0 (128);
        int rl;
        FpiUsbTransfer *transfer;

        rl = vfs491_seal_record (&self->ssl, 0x17, vfs491_capture_cmd,
                                 sizeof (vfs491_capture_cmd), rec);
        if (rl < 0)
          {
            g_free (rec);
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }
        transfer = fpi_usb_transfer_new (_dev);
        fpi_usb_transfer_fill_bulk_full (transfer, VFS491_EP_CMD_OUT, rec, rl, g_free);
        transfer->ssm = ssm;
        transfer->short_is_error = TRUE;
        fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                                 vfs491_async_send_cb, NULL);
      }
      break;

    case ACTIVATE_ARM_RECV:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (_dev);

        fpi_usb_transfer_fill_bulk_full (transfer, VFS491_EP_CMD_IN,
                                         self->rxbuf, 512, NULL);
        transfer->ssm = ssm;
        fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                                 vfs491_arm_recv_cb, NULL);
      }
      break;

    case ACTIVATE_READ:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (_dev);

        fpi_usb_transfer_fill_bulk_full (transfer, VFS491_EP_IMAGE_IN,
                                         self->readbuf, VFS491_READ_SIZE, NULL);
        transfer->ssm = ssm;
        fpi_usb_transfer_submit (transfer, VFS491_READ_TIMEOUT_MS,
                                 fpi_device_get_cancellable (_dev),
                                 vfs491_capture_cb, NULL);
      }
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vfs491_activate_loop_complete (FpiSsm *ssm, FpDevice *_dev, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (_dev);

  self->loop_running = FALSE;

  if (self->deactivating)
    fpi_image_device_deactivate_complete (dev, error);
  else if (error)
    fpi_image_device_session_error (dev, error);
  else
    vfs491_start_scan (dev);
}

static void
vfs491_start_scan (FpImageDevice *dev)
{
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (dev);
  FpiSsm *ssm;

  self->loop_running = TRUE;
  ssm = fpi_ssm_new (FP_DEVICE (dev), vfs491_activate_loop, ACTIVATE_NUM_STATES);
  fpi_ssm_start (ssm, vfs491_activate_loop_complete);
}

/* ------------------------------------------------------------------ handshake */

/* Build and run the SSLv3 handshake as an SSM of its own; on success
 * the session keys live in self->ssl and session_up is TRUE. */

enum {
  HAND_CLIENTHELLO_SEND,
  HAND_CLIENTHELLO_RECV,
  HAND_CLIENTFLIGHT_SEND,
  HAND_CLIENTFLIGHT_RECV,
  HAND_VERIFY,
  HAND_NUM_STATES,
};

struct vfs491_hs_state
{
  guint8  random[32];
  guint8  srandom[32];
  guint8  premaster[48];
  guint8  ch_hs[128];
  int     ch_hslen;
  guint8  server_flight[1024];
  int     server_flightlen;
  guint8  cert_hs[18 + VFS491_MODLEN];
  int     cert_hslen;
  guint8  cke_hs[4 + VFS491_MODLEN];
  int     cke_hslen;
  guint8  cv_hs[4 + VFS491_MODLEN];
  int     cv_hslen;
  guint8  flight[1024];
  int     flightlen;
  guint8  master[48];
  guint8  transcript[1024];
  int     transcriptlen;
};

static int
vfs491_build_clienthello (guint8 *rec, const guint8 random[32])
{
  guint8 body[64];
  int n = 0, m = 0;

  body[n++] = 0x03; body[n++] = 0x00;
  memcpy (body + n, random, 32); n += 32;
  body[n++] = 7;
  memset (body + n, 0, 7); n += 7;      /* 7 zero session-id bytes, as the vendor sends */
  body[n++] = 0x00; body[n++] = 0x06;   /* cipher suites */
  body[n++] = 0x00; body[n++] = 0x44;   /* AES-256-CBC-SHA1 */
  body[n++] = 0x00; body[n++] = 0x43;   /* AES-192 */
  body[n++] = 0x00; body[n++] = 0x42;   /* AES-128 */
  body[n++] = 0x00;                     /* null compression */

  rec[m++] = 0x16; rec[m++] = 0x03; rec[m++] = 0x00;
  rec[m++] = (guint8) ((4 + n) >> 8);
  rec[m++] = (guint8) (4 + n);
  rec[m++] = 0x01; rec[m++] = 0x00; rec[m++] = 0x00;
  rec[m++] = (guint8) n;
  memcpy (rec + m, body, (size_t) n); m += n;
  return m;
}

/* The recv callback used by both handshake read states: the shared
 * vfs491_async_recv_cb needs the reply length, and the flight-send /
 * verify states read it out of the handshake state. */
static void
vfs491_hs_recv_cb (FpiUsbTransfer *transfer, FpDevice *device,
                   gpointer user_data, GError *error)
{
  struct vfs491_hs_state *hs = fpi_ssm_get_data (transfer->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  hs->server_flightlen = (int) transfer->actual_length;
  fpi_ssm_next_state (transfer->ssm);
}

static void
vfs491_handshake_loop (FpiSsm *ssm, FpDevice *_dev)
{
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (_dev);
  struct vfs491_hs_state *hs = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case HAND_CLIENTHELLO_SEND:
      {
        guint8 ch_rec[128];
        guint8 *tunnel;
        int ch_reclen;
        FpiUsbTransfer *transfer;

        GRand *r = g_rand_new ();
        int i;
        for (i = 0; i < 32; i++)
          hs->random[i] = (guint8) g_rand_int (r) & 0xff;
        for (i = 0; i < 48; i++)
          hs->premaster[i] = (guint8) g_rand_int (r) & 0xff;
        g_rand_free (r);
        hs->premaster[0] = 0x03;
        hs->premaster[1] = 0x00;

        ch_reclen = vfs491_build_clienthello (ch_rec, hs->random);
        hs->ch_hslen = ch_reclen - 5;
        memcpy (hs->ch_hs, ch_rec + 5, (size_t) hs->ch_hslen);

        tunnel = g_malloc (3 + ch_reclen);
        tunnel[0] = VFS491_CMD_SSL_TUNNEL;
        tunnel[1] = (guint8) (ch_reclen & 0xff);
        tunnel[2] = (guint8) ((ch_reclen >> 8) & 0xff);
        memcpy (tunnel + 3, ch_rec, (size_t) ch_reclen);

        fp_dbg ("sending ClientHello (%d-byte record)", ch_reclen);
        transfer = fpi_usb_transfer_new (_dev);
        fpi_usb_transfer_fill_bulk_full (transfer, VFS491_EP_CMD_OUT,
                                         tunnel, 3 + ch_reclen, g_free);
        transfer->ssm = ssm;
        transfer->short_is_error = TRUE;
        fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                                 vfs491_async_send_cb, NULL);
      }
      break;

    case HAND_CLIENTHELLO_RECV:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (_dev);

        fpi_usb_transfer_fill_bulk_full (transfer, VFS491_EP_CMD_IN,
                                         self->rxbuf, 512, NULL);
        transfer->ssm = ssm;
        fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                                 vfs491_hs_recv_cb, NULL);
      }
      break;

    case HAND_CLIENTFLIGHT_SEND:
      {
        /* Parse the server flight, build Certificate + CKE + CV, derive
         * keys, seal Finished, send it all in one tunnel. */
        guint8 *resp = self->rxbuf;
        int n = 0;   /* filled by recv cb via actual_length? no: stored below */
        int sh_reclen, sh_hslen, len, r1, fin;
        guint8 rec1[1024], ccs[6] = { 0x14, 0x03, 0x00, 0x00, 0x01, 0x01 };
        guint8 keyblock[136], dig[36], sig[VFS491_MODLEN];
        guint8 fin_hs[40], finrec[128];
        int le = vfs491_modulus_le;
        FpiUsbTransfer *transfer;

        n = hs->server_flightlen;   /* reply length stashed by recv cb */
        if (n < 5 || resp[0] != 0x16 || resp[5] != 0x02)
          {
            fp_err ("no ServerHello (n=%d, first=0x%02x)", n, n > 0 ? resp[0] : 0);
            goto handshake_fail;
          }
        sh_reclen = (resp[3] << 8) | resp[4];
        if (sh_reclen < 43 || 5 + sh_reclen > n ||
            sh_reclen > (int) sizeof (hs->server_flight))
          {
            fp_err ("bad ServerHello length %d (n=%d)", sh_reclen, n);
            goto handshake_fail;
          }
        memcpy (hs->srandom, resp + 11, 32);
        hs->server_flightlen = sh_reclen;
        memcpy (hs->server_flight, resp + 5, (size_t) sh_reclen);
        sh_hslen = sh_reclen;
        fp_dbg ("ServerHello: suite 0x%02x%02x, sid len %d",
                resp[51], resp[52], resp[43]);

        /* Certificate: 00 01 15 00 01 08 00 01 00 00 01 00 01 00 || modulus */
        hs->cert_hs[0] = 0x0b; hs->cert_hs[1] = 0x00;
        hs->cert_hs[2] = 0x01; hs->cert_hs[3] = 0x0e;
        memcpy (hs->cert_hs + 4,
                (const guint8[]){ 0x00, 0x01, 0x15, 0x00, 0x01, 0x08, 0x00, 0x01,
                                  0x00, 0x00, 0x01, 0x00, 0x01, 0x00 }, 14);
        memcpy (hs->cert_hs + 18, self->certmod, VFS491_MODLEN);
        hs->cert_hslen = 18 + VFS491_MODLEN;

        /* ClientKeyExchange: RSA PKCS#1 v1.5 premaster, server key */
        if (vfs491_rsa_pkcs1_encrypt (self->ckemod, VFS491_MODLEN, le,
                                      hs->premaster, 48, hs->cke_hs + 4) < 0)
          {
            fp_err ("CKE RSA encrypt failed");
            goto handshake_fail;
          }
        hs->cke_hs[0] = 0x10; hs->cke_hs[1] = 0x00;
        hs->cke_hs[2] = 0x01; hs->cke_hs[3] = 0x00;
        hs->cke_hslen = 4 + VFS491_MODLEN;

        /* CertificateVerify (0x0f): the sensor's scsSSLHsHashFinish
         * construction keyed by a master secret derived from the
         * premaster, with NO sender label; the 36-byte digest is signed
         * raw (PKCS#1 type 1, no DigestInfo) with the client key
         * (DataID 0x0d). */
        {
          guint8 m2[48];
          int tl = 0;

          vfs491_ssl3_prf (hs->premaster, 48, hs->random, 32,
                           hs->srandom, 32, m2, 48);
          memcpy (hs->transcript + tl, hs->ch_hs, (size_t) hs->ch_hslen);
          tl += hs->ch_hslen;
          memcpy (hs->transcript + tl, hs->server_flight, (size_t) sh_hslen);
          tl += sh_hslen;
          memcpy (hs->transcript + tl, hs->cert_hs, (size_t) hs->cert_hslen);
          tl += hs->cert_hslen;
          memcpy (hs->transcript + tl, hs->cke_hs, (size_t) hs->cke_hslen);
          tl += hs->cke_hslen;
          hs->transcriptlen = tl;

          vfs491_ssl3_finished (m2, hs->transcript, tl, NULL, 0, dig);
          if (vfs491_raw_pkcs1_sign (self->cvkey, dig, 36, sig) < 0)
            {
              fp_err ("CertificateVerify signing failed");
              goto handshake_fail;
            }
        }
        hs->cv_hs[0] = 0x0f; hs->cv_hs[1] = 0x00;
        hs->cv_hs[2] = 0x01; hs->cv_hs[3] = 0x00;
        memcpy (hs->cv_hs + 4, sig, VFS491_MODLEN);
        hs->cv_hslen = 4 + VFS491_MODLEN;

        /* one 0x16 record carrying all three messages */
        len = 0;
        r1 = 0;
        rec1[r1++] = 0x16; rec1[r1++] = 0x03; rec1[r1++] = 0x00;
        r1 += 2;   /* length filled below */
        memcpy (rec1 + r1, hs->cert_hs, (size_t) hs->cert_hslen); r1 += hs->cert_hslen;
        memcpy (rec1 + r1, hs->cke_hs, (size_t) hs->cke_hslen); r1 += hs->cke_hslen;
        memcpy (rec1 + r1, hs->cv_hs, (size_t) hs->cv_hslen); r1 += hs->cv_hslen;
        len = r1 - 5;
        rec1[3] = (guint8) (len >> 8);
        rec1[4] = (guint8) len;
        /* transcript so far: ClientHello + server flight + Certificate +
         * ClientKeyExchange (the CertificateVerify digest above covers
         * exactly this prefix, so it must not be appended yet).  The
         * client Finished and the server Finished both cover the full
         * flight including CertificateVerify. */
        hs->transcriptlen += hs->cv_hslen;
        memcpy (hs->transcript + hs->transcriptlen - hs->cv_hslen,
                hs->cv_hs, (size_t) hs->cv_hslen);

        /* keys */
        vfs491_ssl3_prf (hs->premaster, 48, hs->random, 32, hs->srandom, 32,
                         hs->master, 48);
        vfs491_ssl3_prf (hs->master, 48, hs->srandom, 32, hs->random, 32,
                         keyblock, 136);
        memcpy (self->ssl.cmac, keyblock + 0, 20);
        memcpy (self->ssl.smac, keyblock + 20, 20);
        memcpy (self->ssl.ckey, keyblock + 40, 32);
        memcpy (self->ssl.skey, keyblock + 72, 32);
        memcpy (self->ssl.civ, keyblock + 104, 16);
        memcpy (self->ssl.siv, keyblock + 120, 16);
        self->ssl.send_seq = self->ssl.recv_seq = 0;

        /* client Finished, sealed under the new cipher spec */
        {
          guint8 fin_body[36];

          vfs491_ssl3_finished (hs->master, hs->transcript, hs->transcriptlen,
                                (const guint8[]){ 0x54, 0x4e, 0x4c, 0x43 }, 4,
                                fin_body);
          fin_hs[0] = 0x14; fin_hs[1] = 0x00; fin_hs[2] = 0x00; fin_hs[3] = 0x24;
          memcpy (fin_hs + 4, fin_body, 36);
          fin = vfs491_seal_record (&self->ssl, 0x16, fin_hs, 40, finrec);
          if (fin < 0)
            {
              fp_err ("Failed to seal client Finished");
              goto handshake_fail;
            }
        }

        len = r1;
        memcpy (hs->flight, rec1, (size_t) r1);
        memcpy (hs->flight + len, ccs, 6); len += 6;
        memcpy (hs->flight + len, finrec, (size_t) fin); len += fin;
        hs->flightlen = len;

        {
          guint8 *t = g_malloc ((size_t) len + 3);

          t[0] = VFS491_CMD_SSL_TUNNEL;
          t[1] = (guint8) (len & 0xff);
          t[2] = (guint8) ((len >> 8) & 0xff);
          memcpy (t + 3, hs->flight, (size_t) len);
          fp_dbg ("sending client flight (%d bytes tunneled)", len);
          transfer = fpi_usb_transfer_new (_dev);
          /* Transfer takes ownership and frees it when it completes. */
          fpi_usb_transfer_fill_bulk_full (transfer, VFS491_EP_CMD_OUT,
                                           t, len + 3, g_free);
          transfer->ssm = ssm;
          transfer->short_is_error = TRUE;
          fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                                   vfs491_async_send_cb, NULL);
        }
        return;

      handshake_fail:
        fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      }
      break;

    case HAND_CLIENTFLIGHT_RECV:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (_dev);

        fpi_usb_transfer_fill_bulk_full (transfer, VFS491_EP_CMD_IN,
                                         self->rxbuf, 512, NULL);
        transfer->ssm = ssm;
        fpi_usb_transfer_submit (transfer, VFS491_CMD_TIMEOUT_MS, NULL,
                                 vfs491_hs_recv_cb, NULL);
      }
      break;

    case HAND_VERIFY:
      {
        /* stash reply length for the flight-send state on the next run,
         * parse the server's CCS + Finished (+ optional AppData) */
        guint8 *resp = self->rxbuf;
        int n = hs->server_flightlen;  /* reused: recv cb stores length here */
        int p = 0, verified = 0;

        while (p + 5 <= n)
          {
            guint8 rt = resp[p];
            int rl = (resp[p + 3] << 8) | resp[p + 4];
            guint8 *body = resp + p + 5;

            if (p + 5 + rl > n)
              break;
            if (rt == 0x15)
              {
                fp_err ("handshake rejected: alert level %u desc 0x%02x",
                        rl >= 2 ? body[0] : 0, rl >= 2 ? body[1] : 0);
                goto hs_fail;
              }
            if (rt == 0x16 || rt == 0x17)
              {
                guint8 plain[1024];
                int pl = vfs491_open_record (&self->ssl, rt, body, rl, plain);

                /* Any encrypted record consumes a sequence number, even
                 * if it is application data we do not care about here. */
                if (rt == 0x17)
                  {
                    fp_dbg ("server sent %d bytes of AppData during handshake",
                            pl);
                    p += 5 + rl;
                    continue;
                  }

                if (pl >= 4 && plain[0] == 0x14)
                  {
                    guint8 expect[36];

                    /* Server Finished covers the transcript through the
                     * CertificateVerify only (the vendor never folds a
                     * Finished message into its handshake hash). */
                    vfs491_ssl3_finished (hs->master, hs->transcript,
                                          hs->transcriptlen,
                                          (const guint8[]){ 0x52, 0x56, 0x52, 0x53 }, 4,
                                          expect);
                    if (pl == 40 && memcmp (plain + 4, expect, 36) == 0)
                      verified = 1;
                    else
                      fp_dbg ("server Finished mismatch");
                  }
              }
            p += 5 + rl;
          }

        if (!verified)
          {
            /* Most likely the modulus byte order guess was wrong: the
             * sensor could not decrypt the premaster.  Flip the remembered
             * order so the next attempt gets it right. */
            vfs491_modulus_le = !vfs491_modulus_le;
            fp_err ("SSL handshake failed (server Finished not verified); "
                    "trying modulus %s-endian next time",
                    vfs491_modulus_le ? "little" : "big");
            goto hs_fail;
          }

        fp_dbg ("SSL session established (keys agree)");
        self->session_up = TRUE;
        fpi_ssm_next_state (ssm);
        return;

      hs_fail:
        fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      }
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vfs491_handshake_complete (FpiSsm *ssm, FpDevice *_dev, GError *error)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (_dev);

  /* hs is owned by the SSM (set with g_free as destroy notify) and is
   * released automatically after this callback returns. */
  self->loop_running = FALSE;

  if (error)
    {
      /* A cancelled handshake is an activation failure, not a session
       * failure: the device was never marked active. */
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        fpi_image_device_activate_complete (dev, error);
      else
        fpi_image_device_session_error (dev, error);
      return;
    }
  vfs491_start_scan (dev);
}

/* ------------------------------------------------------------------ activate */

static void
vfs491_dev_activate (FpImageDevice *dev)
{
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (dev);

  self->deactivating = FALSE;
  self->activation_complete = FALSE;

  if (self->session_up)
    {
      vfs491_start_scan (dev);
      return;
    }

  self->loop_running = TRUE;
  {
    struct vfs491_hs_state *hs = g_malloc0 (sizeof (struct vfs491_hs_state));
    FpiSsm *ssm;

    ssm = fpi_ssm_new (FP_DEVICE (dev), vfs491_handshake_loop, HAND_NUM_STATES);
    /* stash the hs state; the recv cb reads the reply length from it */
    fpi_ssm_set_data (ssm, hs, g_free);
    /* replace the plain recv cb for the two recv states */
    fpi_ssm_start (ssm, vfs491_handshake_complete);
  }
}

static void
vfs491_dev_deactivate (FpImageDevice *dev)
{
  FpDeviceVfs491 *self = FPI_DEVICE_VFS491 (dev);

  if (self->loop_running)
    self->deactivating = TRUE;
  else
    fpi_image_device_deactivate_complete (dev, NULL);
}

/* ------------------------------------------------------------------ driver */

static const FpIdEntry vfs491_id_table[] = {
  { .vid = VFS491_USB_VENDOR, .pid = VFS491_USB_PRODUCT },
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_vfs491_init (FpDeviceVfs491 *self)
{
}

static void
fpi_device_vfs491_class_init (FpDeviceVfs491Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = "vfs491";
  dev_class->full_name = "Validity VFS491";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = vfs491_id_table;
  dev_class->scan_type = FP_SCAN_TYPE_SWIPE;

  img_class->img_open = vfs491_dev_open;
  img_class->img_close = vfs491_dev_close;
  img_class->activate = vfs491_dev_activate;
  img_class->deactivate = vfs491_dev_deactivate;

  img_class->bz3_threshold = 20;

  img_class->img_width = VFS491_IMAGE_WIDTH;
  img_class->img_height = -1;
}
