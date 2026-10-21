/* Crypto-fidelity harness: compile the driver source in directly and print
 * the same vectors as the proven client's --selftest, so the ported SSLv3
 * primitives can be diffed against it. */
#include "drivers/vfs491.c"

int
main (void)
{
  guint8 pm[48], cr[32], sr[32], master[48], kb[136], fin[36];
  guint8 hs[64], fin_hs[40], rec[256];
  struct vfs491_ssl_state c;
  int i, rl;

  for (i = 0; i < 48; i++)
    pm[i] = (guint8) i;
  pm[0] = 0x03;
  pm[1] = 0x00;
  for (i = 0; i < 32; i++)
    {
      cr[i] = (guint8) (0x10 + i);
      sr[i] = (guint8) (0x80 + i);
    }
  for (i = 0; i < 64; i++)
    hs[i] = (guint8) i;

  vfs491_ssl3_prf (pm, 48, cr, 32, sr, 32, master, 48);
  vfs491_ssl3_prf (master, 48, sr, 32, cr, 32, kb, 136);
  vfs491_ssl3_finished (master, hs, 64,
                        (const guint8[]){ 0x54, 0x4e, 0x4c, 0x43 }, 4, fin);

  memcpy (c.cmac, kb + 0, 20);
  memcpy (c.smac, kb + 20, 20);
  memcpy (c.ckey, kb + 40, 32);
  memcpy (c.skey, kb + 72, 32);
  memcpy (c.civ, kb + 104, 16);
  memcpy (c.siv, kb + 120, 16);
  c.send_seq = c.recv_seq = 0;

  fin_hs[0] = 0x14; fin_hs[1] = 0; fin_hs[2] = 0; fin_hs[3] = 0x24;
  memcpy (fin_hs + 4, fin, 36);
  rl = vfs491_seal_record (&c, 0x16, fin_hs, 40, rec);

  g_print ("master=");
  for (i = 0; i < 48; i++) g_print ("%02x", master[i]);
  g_print ("\nkeyblock=");
  for (i = 0; i < 136; i++) g_print ("%02x", kb[i]);
  g_print ("\nfinished=");
  for (i = 0; i < 36; i++) g_print ("%02x", fin[i]);
  g_print ("\nrecord=");
  for (i = 0; i < rl; i++) g_print ("%02x", rec[i]);
  g_print ("\n");
  return 0;
}
