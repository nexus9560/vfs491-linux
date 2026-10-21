/*
 * vfs491_session.c -- probe the VFS491 command set and its SSLv3 session layer.
 *
 * Part of vfs491-linux.  Open source; no vendor code.
 *
 * Commands this tool sends (all read-only, no sensor writes anywhere):
 *
 *   0x01 GET_VERSION     -- sensor identity (same as vfs491_probe)
 *   0x19 GET_START_INFO  -- boot/state info the VFS495 tool reads after reset
 *   0x11 SSL tunnel      -- a self-built SSLv3 ClientHello, then read the reply
 *
 * It deliberately STOPS at the ServerHello.  Completing the handshake would
 * need the sensor's RSA-2048 public key (the VFS495 reads it from sensor
 * storage id 10 with an internal function; the host command for that is not
 * known) -- and the VFS495 project, which did reverse the whole SSL crypto
 * byte-exactly, is itself blocked by a sensor-side gate that answers the
 * assembled ClientKeyExchange+Finished flight with fatal alert 0x2f.
 * See docs/ssl-notes.md for the distilled spec and the honest status.
 *
 * The ClientHello is built from the framing documented in
 * reference/vfs495-linux/docs/SSL_PROTOCOL.md; no captured/vendor artefacts
 * are needed for it.  Learn from the reply whether this sensor runs the same
 * proprietary SSLv3 stack (look for the 7-byte "FALCSSL" session id and
 * cipher suite 0x0044) or an alert / something else.
 *
 * Note: GET_START_INFO and an abandoned handshake leave the sensor in a normal
 * (RAM-only) state; unplugging/replugging the sensor resets it if it ever
 * looks stuck.  Nothing here touches OTP, flash or ownership.
 *
 * Build:  make
 * Run:    ./build/vfs491_session [info|hello|all]     (default: all)
 */

#include <libusb-1.0/libusb.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VID 0x138a
#define PID 0x003d

#define EP_CMD_OUT 0x01
#define EP_CMD_IN  0x81
#define EP_IMAGE_IN 0x82

#define CMD_GET_VERSION    0x01
#define CMD_DOWNLOAD_PATCH 0x06
#define CMD_SSL_TUNNEL     0x11
#define CMD_GET_START_INFO 0x19
#define CMD_SPI_READ       0x1f

#define TIMEOUT_MS 2000

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

static int read_all(libusb_device_handle *h, unsigned char ep,
		    unsigned char *out, int cap, unsigned timeout_ms)
{
	int total = 0;

	while (total < cap) {
		int got = 0;
		unsigned t = total ? 100 : timeout_ms;
		int r = libusb_bulk_transfer(h, ep, out + total, cap - total,
					     &got, t);
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

static void cmd_get_version(libusb_device_handle *h)
{
	unsigned char cmd[1] = {CMD_GET_VERSION};
	unsigned char r[64];
	int n = send_cmd(h, cmd, 1, r, sizeof(r));

	printf("GET_VERSION (0x01)\n");
	if (n < 2) {
		printf("  no/short reply (%d bytes)\n", n);
		return;
	}
	printf("  status 0x%04x, %d bytes\n", r[0] | (r[1] << 8), n);
	if (n >= 31)
		printf("  version %u.%u build %u, target %u, product %u, platform 0x%02x,"
		       " security %02x %02x\n",
		       r[10], r[11], r[6] | (r[7] << 8) | (r[8] << 16) | (r[9] << 24),
		       r[12], r[13], r[16], r[24], r[25]);
	if (n >= 30)
		printf("  patch flag 0x%02x, patch signature 0x%08x%s\n", r[17],
		       r[26] | (r[27] << 8) | (r[28] << 16) | ((unsigned)r[29] << 24),
		       r[17] ? "  (patches loaded)" : "  (no patch loaded)");
}

static void cmd_get_start_info(libusb_device_handle *h)
{
	unsigned char cmd[1] = {CMD_GET_START_INFO};
	unsigned char r[256];
	int n = send_cmd(h, cmd, 1, r, sizeof(r));

	printf("GET_START_INFO (0x19)\n");
	if (n <= 0) {
		printf("  no reply\n");
		return;
	}
	printf("  status 0x%04x, %d bytes\n", r[0] | (r[1] << 8), n);
	hexdump("    ", r, n);
}

static int build_clienthello(unsigned char *out, const unsigned char random[32],
			     const unsigned char sid[7])
{
	unsigned char body[64];
	int n = 0;
	int m = 0;

	body[n++] = 0x03;                 /* client_version = SSL 3.0 */
	body[n++] = 0x00;
	memcpy(body + n, random, 32);     /* client_random */
	n += 32;
	body[n++] = 7;                    /* session id length */
	memcpy(body + n, sid, 7);
	n += 7;
	body[n++] = 0x00;                 /* cipher suites length = 6 */
	body[n++] = 0x06;
	body[n++] = 0x00; body[n++] = 0x44;  /* AES-256-CBC-SHA1 (chosen) */
	body[n++] = 0x00; body[n++] = 0x43;  /* AES-192-CBC-SHA1 */
	body[n++] = 0x00; body[n++] = 0x42;  /* AES-128-CBC-SHA1 */
	body[n++] = 0x00;                 /* compression: null */

	/* record: 16 03 00 <u16 len> | handshake 01 <u24 len> <body> */
	out[m++] = 0x16;
	out[m++] = 0x03;
	out[m++] = 0x00;
	out[m++] = (unsigned char)((4 + n) >> 8);
	out[m++] = (unsigned char)(4 + n);
	out[m++] = 0x01;
	out[m++] = 0x00;
	out[m++] = 0x00;
	out[m++] = (unsigned char)n;
	memcpy(out + m, body, n);
	m += n;
	return m;
}

static void cmd_clienthello(libusb_device_handle *h)
{
	unsigned char random[32];
	unsigned char sid[7] = {0};
	unsigned char record[128];
	unsigned char tunnel[132];
	unsigned char r[1024];
	int rec_len, tun_len, n, o = 0, i;

	FILE *f = fopen("/dev/urandom", "rb");
	if (!f || fread(random, 1, 32, f) != 32) {
		fprintf(stderr, "cannot read /dev/urandom\n");
		if (f)
			fclose(f);
		return;
	}
	fclose(f);

	rec_len = build_clienthello(record, random, sid);
	tunnel[0] = CMD_SSL_TUNNEL;
	tunnel[1] = (unsigned char)(rec_len & 0xff);
	tunnel[2] = (unsigned char)((rec_len >> 8) & 0xff);
	memcpy(tunnel + 3, record, rec_len);
	tun_len = 3 + rec_len;

	printf("ClientHello (0x11 tunnel, %d-byte record, %d-byte command)\n", rec_len, tun_len);
	printf("  client_random ");
	for (i = 0; i < 32; i++)
		printf("%02x", random[i]);
	printf("\n  sending: ");
	for (i = 0; i < tun_len && i < 16; i++)
		printf("%02x ", tunnel[i]);
	printf("...\n");

	n = send_cmd(h, tunnel, tun_len, r, sizeof(r));
	if (n <= 0) {
		printf("  no reply (no ServerHello)\n");
		return;
	}
	printf("  reply: %d bytes\n", n);
	hexdump("    ", r, n);

	if (r[0] == CMD_SSL_TUNNEL) {
		o = 3;   /* tunneled record */
		printf("  (reply is tunneled in 0x11)\n");
	}
	if (o >= n) {
		printf("  reply too short to parse\n");
		return;
	}
	if (r[o] == 0x15) {
		printf("  ALERT: level %u desc 0x%02x\n", r[o + 5], r[o + 6]);
		if (r[o + 6] == 0x2f)
			printf("  desc 0x2f is the same proprietary alert the VFS495 "
			       "sensor returns\n");
		return;
	}
	if (r[o] != 0x16) {
		printf("  not a TLS record (first byte 0x%02x)\n", r[o]);
		return;
	}
	if (n > o + 5 && r[o + 5] != 0x02) {
		printf("  handshake type 0x%02x (expected ServerHello 0x02)\n", r[o + 5]);
		return;
	}

	printf("  ServerHello:\n");
	printf("    record len    %u\n", (r[o + 3] << 8) | r[o + 4]);
	printf("    server_random ");
	for (i = 0; i < 32; i++)
		printf("%02x", r[o + 11 + i]);
	printf("\n");
	{
		int sid_len = r[o + 43];
		int p = o + 44;
		printf("    session id    %d bytes: ", sid_len);
		for (i = 0; i < sid_len && p + i < n; i++)
			printf("%c", (r[p + i] >= 0x20 && r[p + i] < 0x7f) ? r[p + i] : '.');
		printf("  (");
		for (i = 0; i < sid_len && p + i < n; i++)
			printf("%02x ", r[p + i]);
		printf(")\n");
		p += sid_len;
		if (p + 3 <= n)
			printf("    cipher suite  0x%02x%02x\n", r[p], r[p + 1]);
		printf("    ServerHelloDone present: %s\n",
		       (p + 4 < n && r[p + 2] == 0x0e) ? "yes" : "unclear");
	}
	printf("  => same proprietary SSLv3 stack as the VFS495 (suite 0x0044, "
	       "\"FALCSSL\" session id)?\n");
}

/*
 * Is the 0x11 refusal a state gate or content-dependent?
 *
 * The VFS495 tool only opens the tunnel after two 0x06 DownloadPatch uploads
 * (the second is "security management") plus 0x1f reads.  We cannot do those
 * without HP's patch blobs, so this sends several 0x11 payloads and compares
 * the status word.  A constant status means the sensor rejects at the command
 * layer (state gate), i.e. it never even looks at the TLS record.
 */
static void cmd_gate(libusb_device_handle *h)
{
	static const struct {
		const char *name;
		int len;
		unsigned char buf[128];
	} cases[] = {
		{"0x11 alone (no length, no record)", 1, {CMD_SSL_TUNNEL}},
		{"0x11 + zero length", 3, {CMD_SSL_TUNNEL, 0x00, 0x00}},
		{"0x11 + 5-byte truncated record", 8,
		 {CMD_SSL_TUNNEL, 0x05, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00}},
		{"0x11 + 8 bytes of garbage", 11,
		 {CMD_SSL_TUNNEL, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11,
		  0x22, 0x33}},
	};
	unsigned char r[256];

	printf("SSL tunnel (0x11) refusal characterisation\n");
	for (unsigned long i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int n = send_cmd(h, cases[i].buf, cases[i].len, r, sizeof(r));
		if (n >= 2)
			printf("  %-36s -> status 0x%04x (%d bytes)\n", cases[i].name,
			       r[0] | (r[1] << 8), n);
		else
			printf("  %-36s -> no reply (%d)\n", cases[i].name, n);
	}
}

/*
 * Reproduce HP's unlock.
 *
 * Ground truth (docs/ssl-notes.md): after GET_VERSION/GET_START_INFO the vendor
 * uploads two DOWNLOAD_PATCH (0x06) blobs with two 0x1f flash reads in between,
 * and only then does the 0x11 tunnel open:
 *
 *   01 19  06<patch1>  01  1f  1f  06<patch2>  01  0x11...
 *
 * The patch bytes are HP firmware (vendor IP), so this tool never contains
 * them: you pass the two files on the command line.  The 0x1f read commands are
 * plain protocol, observed verbatim in the capture.
 */
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
static const unsigned char spi_read_2[] = {
	0x1f, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
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

static unsigned char *read_file(const char *path, int *lenp)
{
	FILE *f = fopen(path, "rb");
	unsigned char *buf;
	long n;

	if (!f) {
		fprintf(stderr, "  cannot open %s\n", path);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (n <= 0) {
		fprintf(stderr, "  %s is empty\n", path);
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n);
	if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
		fprintf(stderr, "  cannot read %s\n", path);
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*lenp = (int)n;
	return buf;
}

static void do_patch(libusb_device_handle *h, const char *label, const char *path)
{
	unsigned char r[64];
	unsigned char *cmd;
	int len, n;

	cmd = read_file(path, &len);
	if (!cmd)
		return;
	{
		unsigned char *buf = malloc((size_t)len + 1);
		if (!buf) {
			free(cmd);
			return;
		}
		buf[0] = CMD_DOWNLOAD_PATCH;
		memcpy(buf + 1, cmd, (size_t)len);
		n = send_cmd(h, buf, len + 1, r, sizeof(r));
		free(buf);
	}
	free(cmd);
	printf("%s DOWNLOAD_PATCH (%s, %d payload bytes): ", label, path, len);
	if (n >= 2)
		printf("status 0x%04x\n", r[0] | (r[1] << 8));
	else
		printf("no reply (%d bytes)\n", n);
}

static void do_spi(libusb_device_handle *h, const unsigned char *cmd, int len,
		   const char *label)
{
	unsigned char r[64];
	unsigned char data[8192];
	int n, got;

	n = send_cmd(h, cmd, len, r, sizeof(r));
	printf("%s (0x1f, %d bytes): ", label, len);
	if (n >= 2)
		printf("status 0x%04x\n", r[0] | (r[1] << 8));
	else
		printf("no reply (%d bytes)\n", n);
	got = read_all(h, EP_IMAGE_IN, data, sizeof(data), 500);
	printf("  EP 0x82 read: %d bytes\n", got);
	if (got > 0)
		printf("  first bytes: %02x %02x %02x %02x ...\n",
		       data[0], data[1], data[2], data[3]);
}

static void cmd_unlock(libusb_device_handle *h, const char *p1, const char *p2,
		       int do_spi_reads)
{
	printf("== HP init replay (patches from user-supplied files) ==\n");
	cmd_get_version(h);
	printf("\n");
	cmd_get_start_info(h);
	printf("\n");

	do_patch(h, "patch #1", p1);
	printf("\n");
	cmd_get_version(h);

	if (do_spi_reads) {
		printf("\n");
		do_spi(h, spi_read_1, sizeof(spi_read_1), "spi read #1");
		do_spi(h, spi_read_2, sizeof(spi_read_2), "spi read #2");
	}

	printf("\n");
	do_patch(h, "patch #2", p2);
	printf("\n");
	cmd_get_version(h);

	printf("\n== tunnel attempt ==\n");
	cmd_clienthello(h);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [info|hello|gate|unlock P1 P2 [--no-spi]|all]\n"
		"\n"
		"  info           GET_VERSION (0x01) and GET_START_INFO (0x19)\n"
		"  hello          send a self-built SSLv3 ClientHello via the 0x11 tunnel\n"
		"  gate           characterise the 0x11 refusal with several payloads\n"
		"  unlock P1 P2   reproduce HP's init: upload the two 0x06 patches\n"
		"                 (P1 = flcn_patch302810, P2 = the 1300 B patch both from\n"
		"                 files *you* supply), do the two 0x1f reads, then send\n"
		"                 the ClientHello.  --no-spi skips the 0x1f reads.\n"
		"  all            info + gate + hello (default)\n"
		"\n"
		"The unlock patches land in sensor RAM only.  No sensor writes.\n", argv0);
}

int main(int argc, char **argv)
{
	int do_info = 1, do_hello = 1, do_gate = 1, do_unlock = 0;
	int unlock_spi = 1;
	const char *p1 = NULL, *p2 = NULL;
	libusb_device **list = NULL;
	libusb_device *found = NULL;
	libusb_device_handle *handle = NULL;
	ssize_t n;

	if (argc > 1) {
		if (!strcmp(argv[1], "info")) {
			do_hello = do_gate = 0;
		} else if (!strcmp(argv[1], "hello")) {
			do_info = do_gate = 0;
		} else if (!strcmp(argv[1], "gate")) {
			do_info = do_hello = 0;
		} else if (!strcmp(argv[1], "unlock")) {
			int i;
			do_info = do_hello = do_gate = 0;
			do_unlock = 1;
			if (argc < 4) {
				usage(argv[0]);
				return 2;
			}
			p1 = argv[2];
			p2 = argv[3];
			for (i = 4; i < argc; i++)
				if (!strcmp(argv[i], "--no-spi"))
					unlock_spi = 0;
		} else if (!strcmp(argv[1], "all")) {
			/* default: everything */
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (libusb_init(NULL) < 0) {
		fprintf(stderr, "libusb_init failed\n");
		return 2;
	}
	n = libusb_get_device_list(NULL, &list);
	if (n < 0) {
		libusb_exit(NULL);
		return 2;
	}
	for (ssize_t i = 0; i < n; i++) {
		struct libusb_device_descriptor dd;
		if (libusb_get_device_descriptor(list[i], &dd) < 0)
			continue;
		if (dd.idVendor == VID && dd.idProduct == PID) {
			found = list[i];
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

	printf("VFS491 at bus %u device %u\n\n", libusb_get_bus_number(found),
	       libusb_get_device_address(found));

	if (do_unlock) {
		cmd_unlock(handle, p1, p2, unlock_spi);
		goto release;
	}
	if (do_info) {
		cmd_get_version(handle);
		printf("\n");
		cmd_get_start_info(handle);
		if (do_hello || do_gate)
			printf("\n");
	}
	if (do_gate) {
		cmd_gate(handle);
		if (do_hello)
			printf("\n");
	}
	if (do_hello)
		cmd_clienthello(handle);

release:
	libusb_release_interface(handle, 0);
close:
	libusb_close(handle);
out:
	libusb_free_device_list(list, 1);
	libusb_exit(NULL);
	return 0;
}
