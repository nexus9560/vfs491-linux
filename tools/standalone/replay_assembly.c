/* Offline harness: replay either a captured EP 0x82 stream or a driver
 * raw-row dump through the exact assembly path and write a PGM.  Build-time
 * only helper, lives outside the libfprint tree.
 *
 * Usage:
 *   replay_assembly <in> <out.pgm> [width] [search_offset] [resolution]
 *
 * <in> may be:
 *   - concatenated 288-byte encrypted scan lines (original capture), or
 *   - a "VFS491RAW1" file written by FP_VFS491_RAW (descrambled rows).
 */
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libfprint/fpi-assembling.h"
#include "libfprint/fpi-image.h"

#define LINE_SIZE   288
#define LINE_HDR    8
#define LINE_WIDTH  264
#define IMAGE_WIDTH 200
#define MAX_HEIGHT  5000

static const guint16 vfs491_descramble[LINE_WIDTH] = {
#include "vfs491_descramble_body.inc"
};

static unsigned char
get_pixel (struct fpi_line_asmbl_ctx *ctx, GSList *row, unsigned x)
{
  (void) ctx;
  return ((const guint8 *) row->data)[x];
}

static int
get_deviation (struct fpi_line_asmbl_ctx *ctx, GSList *a, GSList *b)
{
  const guint8 *pa = a->data, *pb = b->data;
  int sum = 0;
  unsigned x;

  for (x = 0; x < ctx->line_width; x++)
    sum += abs ((int) pa[x] - (int) pb[x]);
  return sum / (int) ctx->line_width;
}

int
main (int argc, char **argv)
{
  gchar *data;
  gsize len, i;
  GSList *rows = NULL;
  guint nrows = 0;
  guint row_width = LINE_WIDTH;
  guint width = IMAGE_WIDTH;
  int search_offset = 30;
  int resolution = 10;
  FpImage *img;
  FILE *f;

  if (argc < 3 || !g_file_get_contents (argv[1], &data, &len, NULL))
    return 1;

  if (argc > 3)
    width = (guint) MAX (1, atoi (argv[3]));
  if (argc > 4)
    search_offset = MAX (1, atoi (argv[4]));
  if (argc > 5)
    resolution = MAX (1, atoi (argv[5]));

  if (len >= 18 && memcmp (data, "VFS491RAW1", 10) == 0)
    {
      guint32 hdr[2];

      memcpy (hdr, data + 10, sizeof (hdr));
      row_width = GUINT32_FROM_LE (hdr[0]);
      nrows = GUINT32_FROM_LE (hdr[1]);

      if (row_width == 0 || row_width > LINE_WIDTH ||
          18 + (gsize) row_width * nrows > len)
        {
          g_printerr ("bad raw header: width=%u rows=%u file=%zu\n",
                      row_width, nrows, len);
          g_free (data);
          return 1;
        }

      for (i = 0; i < nrows; i++)
        rows = g_slist_prepend (rows, g_memdup2 (data + 18 + i * row_width,
                                                 row_width));
    }
  else
    {
      for (i = 0; i + LINE_SIZE <= len; )
        {
          const guint8 *l = (const guint8 *) data + i;

          if (l[0] == 1 && (l[1] == 1 || l[1] == 0xfe) &&
              l[4] == 8 && l[5] == 8 && l[6] == 0x18 && l[7] == 0)
            {
              guint8 row[LINE_WIDTH];
              guint j;

              for (j = 0; j < LINE_WIDTH; j++)
                row[vfs491_descramble[j]] = l[LINE_HDR + j];
              rows = g_slist_prepend (rows, g_memdup2 (row, LINE_WIDTH));
              nrows++;
              i += LINE_SIZE;
            }
          else
            {
              i++;
            }
        }
    }

  g_free (data);
  rows = g_slist_reverse (rows);
  width = MIN (width, row_width);
  g_print ("rows=%u row_width=%u using width=%u search=%d resolution=%d\n",
           nrows, row_width, width, search_offset, resolution);

  if (nrows < 2)
    {
      g_slist_free_full (rows, g_free);
      return 1;
    }

  {
    struct fpi_line_asmbl_ctx ctx = {
      .line_width = width,
      .max_height = MAX_HEIGHT,
      .resolution = resolution,
      .median_filter_size = 25,
      .max_search_offset = search_offset,
      .get_deviation = get_deviation,
      .get_pixel = get_pixel,
    };

    img = fpi_assemble_lines (&ctx, rows, nrows);
  }

  if (!img)
    {
      g_slist_free_full (rows, g_free);
      return 1;
    }

  g_print ("image %ux%u ppmm=%f\n", img->width, img->height, img->ppmm);

  f = fopen (argv[2], "wb");
  if (!f)
    {
      g_slist_free_full (rows, g_free);
      return 1;
    }
  fprintf (f, "P5\n%u %u\n255\n", img->width, img->height);
  fwrite (img->data, 1, (size_t) img->width * img->height, f);
  fclose (f);

  g_slist_free_full (rows, g_free);
  return 0;
}
