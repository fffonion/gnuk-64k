#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void
print_octets (const uint8_t *p, int len)
{
  int i;

  for (i = 0; i < len; i++)
    printf ("%02x", p[i]);
  puts ("");
}

#define MAXLINE 4096
#define MAXHASH 256

static int lineno;
static int test_no;
static uint8_t msg[MAXLINE];
static size_t msglen;
static size_t outputlen;
static uint8_t hash[MAXHASH];

static const char *
skip_white_space (const char *l)
{
  while (*l == ' ' || *l == '\t')
    l++;

  return l;
}

static int
read_hex_4bit (char c)
{
  int r;

  if (c >= '0' && c <= '9')
    r = c - '0';
  else if (c >= 'a' && c <= 'f')
    r = c - 'a' + 10;
  else if (c >= 'A' && c <= 'F')
    r = c - 'A' + 10;
  else
    r = -1;
  return r;
}

static int
read_hex_8bit (const char **l_p)
{
  const char *l = *l_p;
  int r, v;

  r = read_hex_4bit (*l++);
  if (r < 0)
    return -1;
  v = r*16;
  r = read_hex_4bit (*l++);
  if (r < 0)
    return -1;
  v += r;

  *l_p = l;
  return v;
}

static int
read_octets (uint8_t *out, const char *l, int len)
{
  int i, r;

  for (i = 0; i < len; i++)
    {
      r = read_hex_8bit (&l);
      if (r < 0)
	return -1;
      out[i] = r;
    }

  return 0;
}

static int
read_testcase (void)
{
  ssize_t r;
  size_t len = 0;
  char *line = NULL;
  int start = 0;
  int err = 0;
  int count = -1;
  int outputlen0 = -1;
  int outputlen1 = -1;
  int msglen0 = -1;
  int msglen1 = -1;

  memset (msg, 0, sizeof (msg));
  memset (hash, 0, sizeof (hash));

  while (1)
    {
      lineno++;
      r = getline (&line, &len, stdin);
      if (r < 0)
	{
	  /* EOF */
	  if (!start)
	    err = -1;
          return err;
	}
      len = r;	       /* We don't need allocated size, but length.  */
      if (len >= MAXLINE)
	{
	  fprintf (stderr, "Line too long: %d: >= %d\n", lineno, MAXLINE);
	  err = -1;
	  break;
	}

      if (r == 1 && *line == '\n')
	{
	  if (start)
	    break;		/* Done. */
	  else
	    continue; /* Ignore blank line before start.  */
	}

      if (r > 0 && *line == '#') /* Ignore comment line.  */
	continue;

      if (r > 0 && *line == '[') /* Ignore comment line.  */
	continue;

      start = 1;
      if (r > 7 && strncmp (line, "COUNT =", 7) == 0)
	count = strtol (line+7, NULL, 10);
      else if (r > 5 && strncmp (line, "Len =", 5) == 0)
	msglen0 = strtol (line+5, NULL, 10);
      else if (r > 11 && strncmp (line, "Outputlen =", 11) == 0)
	outputlen0 = strtol (line+11, NULL, 10);
      else if (r > 5 && strncmp (line, "Msg =", 5) == 0)
	{
	  const char *l = skip_white_space (line+5);
          msglen1 = (line+len-1-l)/2 * 8;
	  if (read_octets (msg, l, msglen1/8) < 0)
	    {
	      fprintf (stderr, "msg read_octets: %d\n", lineno);
	      err = -1;
	      break;
	    }
	}
      else if (r > 8 && strncmp (line, "Output =", 8) == 0)
	{
	  const char *l = skip_white_space (line+8);
          outputlen1 = (line+len-1-l)/2 * 8;
	  if (read_octets (hash, l, outputlen1/8) < 0)
	    {
	      fprintf (stderr, "output read_octets: %d\n", lineno);
	      err = -1;
	      break;
	    }
	}
      else
	{
	  fprintf (stderr, "Garbage line: %d: %s", lineno, line);
	  err = -1;
	  break;
	}
    }

  free (line);
  if (count != -1)
    test_no = count;
  else
    test_no++;
  if (outputlen != -1)
    outputlen = outputlen0;
  else
    outputlen = 256;
  if (msglen0 != -1 && (msglen0+7)/8 != msglen1/8 && msglen0 != 0)
    {
      fprintf (stderr, "Wrong Len: %d (%d != %d)\n", lineno, msglen0, msglen1);
      err = -1;
    }
  else if (msglen1 != -1)
    msglen = msglen1;
  else
    {
      fprintf (stderr, "No Msg: %d\n", lineno);
      err = -1;
    }
  return err;
}


#include "shake256.h"

int
main (int argc, char *argv[])
{
  shake_context ctx;
  int all_good = 1;
  int r;
  uint8_t hash_calculated[MAXHASH];

  while (1)
    {
      r = read_testcase ();
      if (r < 0)
	break;

      shake256_start (&ctx);
      shake256_update (&ctx, msg, (msglen+7)/8);
      shake256_finish (&ctx, (uint8_t *)hash_calculated, (outputlen+7)/8);

      if (memcmp (hash, hash_calculated, (outputlen+7)/8) != 0)
	{
	  printf ("ERR: %d: ", test_no);
	  print_octets (hash_calculated, (outputlen+7)/8);
	  all_good = 0;
	  continue;
	}

      printf ("%d\n", test_no);
    }
  return all_good == 1?0:1;
}
