/*
 * vfs491_probe.c -- read-only probe for the Validity VFS491 (USB 138a:003d)
 *
 * Part of vfs491-linux.  Open source; no vendor code.
 *
 * What it does
 *   - finds 138a:003d
 *   - prints device / configuration / interface / endpoint descriptors
 *   - sends GET_VERSION (command 0x01) on bulk OUT 0x01 and decodes the reply
 *     that comes back on bulk IN 0x81
 *
 * GET_VERSION only reads the sensor's version block.  This probe implements
 * that one command and nothing else; it never writes to the sensor.
 *
 * DO NOT implement or send these, ever -- they write permanently to the
 * sensor's OTP memory, flash or ownership state:
 *     provision, write_otp, spiflashwrite, setowner, resetowner,
 *     makeprod, serialize, set_prod_opts
 *
 * Build:  make                (needs libusb-1.0-devel + pkg-config)
 * Run:    ./build/vfs491_probe [--raw] [--repeat N] [--timeout MS] [--list]
 *
 * No root needed on Fedora: systemd-logind grants the seated user an ACL on
 * the device node (/dev/bus/usb/<bus>/<dev> -> user:<you>:rw-).
 */

#include <libusb-1.0/libusb.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VID 0x138a
#define PID 0x003d

/* Endpoint map (confirmed from the device descriptor, see docs/protocol.md). */
#define EP_CMD_OUT 0x01 /* bulk OUT  - host -> sensor commands                */
#define EP_CMD_IN  0x81 /* bulk IN   - sensor -> host command replies         */
#define EP_IMG_IN  0x82 /* bulk IN   - image / scan-line data                 */
#define EP_IRQ_IN  0x83 /* interrupt IN, 8 bytes - finger / status events     */

#define CMD_GET_VERSION    0x01
#define VERSION_REPLY_MAX  0x26 /* 38 bytes */

static const char *TARGETS[] = {NULL, "ROM", "FPGA", "RTLSIM", "ISS", "FPGADBG"};
static const char *PRODUCTS[] = {NULL,   "Falcon",  "Raptor",     "Falconusb",
                                 "Falconspi", "Raptorusb", "Raptorspi"};

static const char *xfer_name(uint8_t attr)
{
	switch (attr & 0x03) {
	case LIBUSB_TRANSFER_TYPE_CONTROL: return "control";
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS: return "isochronous";
	case LIBUSB_TRANSFER_TYPE_BULK: return "bulk";
	case LIBUSB_TRANSFER_TYPE_INTERRUPT: return "interrupt";
	}
	return "?";
}

static const char *ep_note(uint8_t addr)
{
	switch (addr) {
	case EP_CMD_OUT: return "commands out (host -> sensor)";
	case EP_CMD_IN:  return "command replies in";
	case EP_IMG_IN:  return "image / scan-line data in";
	case EP_IRQ_IN:  return "interrupt in (8 B) - events";
	}
	return "";
}

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

static void dump_descriptors(libusb_device *dev)
{
	struct libusb_device_descriptor dd;
	if (libusb_get_device_descriptor(dev, &dd) < 0) {
		fprintf(stderr, "cannot read device descriptor\n");
		return;
	}

	printf("device descriptor\n");
	printf("  idVendor:idProduct  %04x:%04x\n", dd.idVendor, dd.idProduct);
	printf("  bcdUSB              %x.%02x\n", dd.bcdUSB >> 8, dd.bcdUSB & 0xff);
	printf("  bcdDevice           %x.%02x\n", dd.bcdDevice >> 8, dd.bcdDevice & 0xff);
	printf("  bDeviceClass        %02x/%02x/%02x (class/subclass/protocol)\n",
	       dd.bDeviceClass, dd.bDeviceSubClass, dd.bDeviceProtocol);
	printf("  bMaxPacketSize0     %u\n", dd.bMaxPacketSize0);
	printf("  num configurations  %u\n", dd.bNumConfigurations);

	for (uint8_t c = 0; c < dd.bNumConfigurations; c++) {
		struct libusb_config_descriptor *cd = NULL;
		if (libusb_get_config_descriptor(dev, c, &cd) < 0)
			continue;

		printf("configuration %u\n", cd->bConfigurationValue);
		printf("  %u interface(s), bmAttributes 0x%02x, bMaxPower %u mA\n",
		       cd->bNumInterfaces, cd->bmAttributes, cd->MaxPower * 2);

		for (uint8_t i = 0; i < cd->bNumInterfaces; i++) {
			const struct libusb_interface *iface = &cd->interface[i];
			for (int a = 0; a < iface->num_altsetting; a++) {
				const struct libusb_interface_descriptor *id = &iface->altsetting[a];
				printf("  interface %u alt %u: class %02x/%02x/%02x, %u endpoint(s)\n",
				       id->bInterfaceNumber, id->bAlternateSetting,
				       id->bInterfaceClass, id->bInterfaceSubClass,
				       id->bInterfaceProtocol, id->bNumEndpoints);
				for (uint8_t e = 0; e < id->bNumEndpoints; e++) {
					const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
					int in = (ed->bEndpointAddress & LIBUSB_ENDPOINT_IN) != 0;
					printf("    0x%02x %-9s %s  maxpacket %u  interval %u   %s\n",
					       ed->bEndpointAddress,
					       xfer_name(ed->bmAttributes),
					       in ? "IN " : "OUT",
					       ed->wMaxPacketSize, ed->bInterval,
					       ep_note(ed->bEndpointAddress));
				}
			}
		}
		libusb_free_config_descriptor(cd);
	}
}

static void print_string(libusb_device_handle *h, uint8_t index, const char *label)
{
	unsigned char buf[128];
	int n;
	if (!index)
		return;
	n = libusb_get_string_descriptor_ascii(h, index, buf, sizeof(buf));
	if (n > 0)
		printf("  %-18s %.*s\n", label, n, buf);
}

static int get_version(libusb_device_handle *h, unsigned timeout_ms, int dump_raw)
{
	unsigned char cmd[1] = {CMD_GET_VERSION};
	unsigned char reply[256];
	int xfer = 0;
	int total = 0;
	int r;

	r = libusb_bulk_transfer(h, EP_CMD_OUT, cmd, sizeof(cmd), &xfer, timeout_ms);
	if (r < 0) {
		fprintf(stderr, "GET_VERSION: bulk OUT failed: %s\n", libusb_error_name(r));
		return -1;
	}

	/* First read gets the bulk of the reply; keep reading while the sensor
	 * has more (a short read or a timeout ends the loop). */
	while (total < VERSION_REPLY_MAX) {
		int got = 0;
		unsigned t = total ? (timeout_ms > 100 ? 100 : timeout_ms) : timeout_ms;
		r = libusb_bulk_transfer(h, EP_CMD_IN, reply + total,
					 VERSION_REPLY_MAX - total, &got, t);
		if (r == LIBUSB_ERROR_TIMEOUT || r == LIBUSB_ERROR_PIPE)
			break;
		if (r < 0) {
			fprintf(stderr, "GET_VERSION: bulk IN failed: %s\n",
				libusb_error_name(r));
			return -1;
		}
		if (got == 0)
			break;
		total += got;
	}

	if (total < 2) {
		fprintf(stderr, "GET_VERSION: short reply (%d bytes)\n", total);
		return -1;
	}

	printf("GET_VERSION (command 0x01) -> %d byte(s) on 0x%02x\n", total, EP_CMD_IN);
	hexdump("  ", reply, total < 40 ? total : 40);

	{
		uint16_t status = (uint16_t)(reply[0] | (reply[1] << 8));
		printf("  status              0x%04x%s\n", status, status ? "  (non-zero!)" : "");
	}

	if (total < 31) {
		printf("  (reply too short to decode the version block)\n");
		return 0;
	}

	{
		uint32_t buildtime = (uint32_t)reply[2] | ((uint32_t)reply[3] << 8) |
				     ((uint32_t)reply[4] << 16) | ((uint32_t)reply[5] << 24);
		uint32_t buildnum = (uint32_t)reply[6] | ((uint32_t)reply[7] << 8) |
				    ((uint32_t)reply[8] << 16) | ((uint32_t)reply[9] << 24);
		uint8_t vmajor = reply[10], vminor = reply[11];
		uint8_t target = reply[12], product = reply[13];
		uint8_t siliconrev = reply[14], formalrel = reply[15];
		uint8_t platform = reply[16], patch = reply[17];
		uint32_t patchsig = (uint32_t)reply[26] | ((uint32_t)reply[27] << 8) |
				    ((uint32_t)reply[28] << 16) | ((uint32_t)reply[29] << 24);

		printf("  version             %u.%u build %u\n", vmajor, vminor, buildnum);
		printf("  build time          0x%08x\n", buildtime);
		printf("  target              %u %s\n", target,
		       target < 6 ? TARGETS[target] : "?");
		printf("  product             %u %s\n", product,
		       product < 7 ? PRODUCTS[product] : "?");
		printf("  siliconrev/formalrel %u / %u\n", siliconrev, formalrel);
		printf("  platform            0x%02x\n", platform);
		printf("  patch               %u\n", patch);
		printf("  security bytes      %02x %02x   (VFS491 expected 01 30, VFS495 01 7d)\n",
		       reply[24], reply[25]);
		printf("  patch signature     0x%08x\n", patchsig);
		printf("  serial (18-23)      %02x %02x %02x %02x %02x %02x\n",
		       reply[18], reply[19], reply[20], reply[21], reply[22], reply[23]);
		printf("  iface id            %u\n", reply[30]);
		if (total > 31) {
			printf("  trailing bytes      ");
			for (int i = 31; i < total; i++)
				printf("%02x ", reply[i]);
			printf("  (unknown)\n");
		}
	}

	if (dump_raw && total > 0)
		printf("  (raw reply printed above)\n");

	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"\n"
		"  --list            list the USB devices and exit\n"
		"  --raw             (accepted; raw reply is always printed)\n"
		"  --repeat N        send GET_VERSION N times (default 1)\n"
		"  --timeout MS      bulk timeout (default 1000)\n"
		"  -h, --help        this text\n"
		"\n"
		"Read-only: this probe only implements command 0x01 GET_VERSION.\n",
		argv0);
}

int main(int argc, char **argv)
{
	unsigned timeout_ms = 1000;
	int repeat = 1;
	int list_only = 0;
	libusb_device **list = NULL;
	libusb_device *found = NULL;
	libusb_device_handle *handle = NULL;
	ssize_t n;
	int rc = 2;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--list")) {
			list_only = 1;
		} else if (!strcmp(argv[i], "--raw")) {
			/* raw output is always shown */
		} else if (!strcmp(argv[i], "--repeat") && i + 1 < argc) {
			repeat = atoi(argv[++i]);
			if (repeat < 1) repeat = 1;
		} else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
			timeout_ms = (unsigned)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
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
		fprintf(stderr, "libusb_get_device_list failed\n");
		libusb_exit(NULL);
		return 2;
	}

	if (list_only) {
		for (ssize_t i = 0; i < n; i++) {
			struct libusb_device_descriptor dd;
			if (libusb_get_device_descriptor(list[i], &dd) < 0)
				continue;
			printf("%04x:%04x  bus %u device %u%s\n", dd.idVendor, dd.idProduct,
			       libusb_get_bus_number(list[i]),
			       libusb_get_device_address(list[i]),
			       (dd.idVendor == VID && dd.idProduct == PID) ? "   <-- VFS491" : "");
		}
		libusb_free_device_list(list, 1);
		libusb_exit(NULL);
		return 0;
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
		fprintf(stderr, "VFS491 (138a:003d) not found on USB.\n");
		fprintf(stderr, "Is it enabled in the BIOS?  lsusb | grep 138a\n");
		goto out;
	}

	printf("VFS491 found at bus %u device %u\n", libusb_get_bus_number(found),
	       libusb_get_device_address(found));
	printf("(device node: /dev/bus/usb/%03u/%03u)\n\n",
	       libusb_get_bus_number(found), libusb_get_device_address(found));

	dump_descriptors(found);

	if (libusb_open(found, &handle) < 0) {
		fprintf(stderr, "\ncannot open the device - check `ls -l /dev/bus/usb/%03u/%03u`\n",
			libusb_get_bus_number(found), libusb_get_device_address(found));
		goto out;
	}

	printf("\nstrings\n");
	print_string(handle, 1, "serial?");
	print_string(handle, 2, "product?");
	print_string(handle, 3, "manufacturer?");

#if LIBUSB_API_VERSION >= 0x01000102
	libusb_set_auto_detach_kernel_driver(handle, 1);
#endif
	if (libusb_claim_interface(handle, 0) < 0) {
		fprintf(stderr, "cannot claim interface 0 (in use by another driver?)\n");
		goto close;
	}

	printf("\n");
	for (int i = 0; i < repeat; i++) {
		if (repeat > 1)
			printf("--- attempt %d/%d ---\n", i + 1, repeat);
		if (get_version(handle, timeout_ms, 1) < 0) {
			rc = 2;
			goto release;
		}
	}

	rc = 0;

release:
	libusb_release_interface(handle, 0);
close:
	libusb_close(handle);
out:
	libusb_free_device_list(list, 1);
	libusb_exit(NULL);
	return rc;
}
