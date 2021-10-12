#include <stdint.h>
#include <string.h>
#include "p448.h"



static p448_t Gx[1] = { { {
      0x070cc05e, 0x026a82bc, 0x00938e26, 0x080e18b0,
      0x0511433b, 0x0f72ab66, 0x0412ae1a, 0x0a3d3a46,
      0x0a6de324, 0x00f1767e, 0x04657047, 0x036da9e1,
      0x05a622bf, 0x0ed221d1, 0x066bed0d, 0x04f1970c
    }
  }
};

static p448_t Gy[1] = { { {
      0x0230fa14, 0x008795bf, 0x07c8ad98, 0x0132c4ed,
      0x09c4fdbd, 0x01ce67c3, 0x073ad3ff, 0x005a0c2d,
      0x07789c1e, 0x0a398408, 0x0a73736c, 0x0c7624be,
      0x003756c9, 0x02488762, 0x016eb6bc, 0x0693f467
    }
  }
};

static void
compute_kG_448 (p448_t x[1], p448_t y[1], int k)
{
  int i, j;
  p448_t x0[1], y0[1], z0[1]; /* P0 */
  p448_t x1[1], y1[1], z1[1]; /* P1 */

  /* P0 <= O */
  memset (x0, 0, sizeof (p448_t));
  memset (y0, 0, sizeof (p448_t));
  memset (z0, 0, sizeof (p448_t));
  y0->limb[0] = 1;
  z0->limb[0] = 1;

  for (i = 0; i < k; i++)
    {
      p448_t a[1], b[1], c[1], d[1];
      p448_t e[1], f[1], g[1], h[1];
      p448_t tmp0[1], tmp1[1];

      /* Point addition P1 <= P0 + G */
      p448_sqr (b, z0);
      p448_mul (c, x0, Gx);
      p448_mul (d, y0, Gy);
      p448_mul (tmp0, c, d);
      p448_mul_39081 (e, tmp0);
      p448_add (f, b, e);
      p448_sub (g, b, e);
      p448_add (tmp0, x0, y0);
      p448_add (tmp1, Gx, Gy);
      p448_mul (h, tmp0, tmp1);
      p448_sub (tmp0, h, c);
      p448_sub (tmp1, tmp0, d);
      p448_mul (tmp0, f, tmp1);
      p448_mul (x1, z0, tmp0);
      p448_sub (tmp0, d, c);
      p448_mul (tmp1, g, tmp0);
      p448_mul (y1, z0, tmp1);
      p448_mul (z1, f, g);
      /*
        A = Z1*Z2
        B = A^2
        C = X1*X2
        D = Y1*Y2
        E = d*C*D
        F = B-E
        G = B+E
        H = (X1+Y1)*(X2+Y2)
        X3 = A*F*(H-C-D)
        Y3 = A*G*(D-C)
        Z3 = F*G
      */

      /* Point copy P0 <= P1 */
      *x0 = *x1;
      *y0 = *y1;
      *z0 = *z1;
    }

  /* Convert to affine coordinate.  */
  p448_inv (z1, z0);
  p448_mul (x, x0, z1);
  p448_mul (y, y0, z1);
}


#include <stdio.h>

static void
printout_hex (uint32_t *p, int len)
{
  int i, j;

  for (i = 0; i < len / 4; i++)
    {
      for (j = 0; j < 4; j++)
        printf ("0x%08x, ", p[i*4+j]);
      puts ("");
    }
  puts ("");
}


int
main (int argc, const char *argv[])
{
  p448_t x[1], y[1];
  int i;

  for (i = 1; i < 16; i++)
    {
      compute_kG_448 (x, y, i);
      printout_hex ((uint32_t *)x, 16);
      printout_hex ((uint32_t *)y, 16);
      puts ("");
    }
}
