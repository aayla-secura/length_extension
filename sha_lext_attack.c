#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#ifdef USE_SHA256
typedef SHA256_CTX ctx_t;
#  define CBLOCK_LEN SHA256_CBLOCK
#  define MD_LEN     SHA256_DIGEST_LENGTH
#  define CTX_INIT   SHA256_Init
#  define CTX_UPDATE SHA256_Update
#  define CTX_FINAL  SHA256_Final
#  define CTX_DFMT   "%08x"
// length of message is 8-byte big-endian
#  define CBLOCK_AVAIL_LEN  (CBLOCK_LEN - 1 - 8)
#  define CTX_DLEN   32
#  define CTX_LMASK  0xFFFFFFFF
#else
typedef SHA512_CTX ctx_t;
#  define CBLOCK_LEN SHA512_CBLOCK
#  define MD_LEN     SHA512_DIGEST_LENGTH
#  define CTX_INIT   SHA512_Init
#  define CTX_UPDATE SHA512_Update
#  define CTX_FINAL  SHA512_Final
#  define CTX_DFMT   "%016llx"
// length of message is 16-bit big-endian
#  define CBLOCK_AVAIL_LEN  (CBLOCK_LEN - 1 - 16)
#  define CTX_DLEN   64 // in bits
#  define CTX_LMASK  0xFFFFFFFFFFFFFFFF
#endif

#define MD_HEXLEN  (MD_LEN*2)
#define CTX_DHEXLEN (CTX_DLEN >> 2) // 2 hex chars per byte

#define DUMP_ROW_LEN  8 // how many bytes per row when dumping buf
#define DUMP_OFF_LEN  5 // how many digits to use for the offset

#define ANSI_FG_RED     "\x1b[31m"
#define ANSI_FG_GREEN   "\x1b[32m"
#define ANSI_FG_YELLOW  "\x1b[33m"
#define ANSI_FG_BLUE    "\x1b[34m"
#define ANSI_FG_MAGENTA "\x1b[35m"
#define ANSI_FG_CYAN    "\x1b[36m"
#define ANSI_BG_RED     "\x1b[41m"
#define ANSI_BG_GREEN   "\x1b[42m"
#define ANSI_BG_YELLOW  "\x1b[43m"
#define ANSI_BG_BLUE    "\x1b[44m"
#define ANSI_BG_MAGENTA "\x1b[45m"
#define ANSI_BG_CYAN    "\x1b[46m"
#define ANSI_RESET      "\x1b[0m"
#define ANSI_BOLD       "\x1b[1m"

#define DEFAULT_MIN_MSG_L 1
#define DEFAULT_MAX_MSG_L 1024
#define DEFAULT_STEP      1

static void usage (const char* progname);
static int hexchar2num (char c);
static int set_ctx_md (ctx_t* ctx, const char* hex);
static void print_md (const unsigned char* md);
static void dump_buf (void* buf_, uint32_t len);
static void dump_ctx (ctx_t* ctx);

static void
usage (const char* progname)
{
	fprintf (stderr,
		ANSI_BOLD "Usage: " ANSI_RESET "%s " ANSI_FG_CYAN "<options>" ANSI_RESET "\n\n"
		ANSI_BOLD "Options:\n" ANSI_RESET
		ANSI_FG_CYAN "  -m <str>     " ANSI_RESET "Message to append.\n"
		ANSI_FG_CYAN "  -d <hex str> " ANSI_RESET "Digest to begin with.\n"
		ANSI_FG_CYAN "  -l <int>     " ANSI_RESET "Minimum length of salt + original message.\n"
		             "               "            "Default is %d.\n"
		ANSI_FG_CYAN "  -L <int>     " ANSI_RESET "Maximum length of salt + original message.\n"
		             "               "            "Default is %d.\n"
		ANSI_FG_CYAN "  -s <int>     " ANSI_RESET "Step to increment length.\n"
		             "               "            "Default is %d.\n",
		progname, DEFAULT_MIN_MSG_L, DEFAULT_MAX_MSG_L, DEFAULT_STEP);
	exit (EXIT_FAILURE);
}

int main (int argc, char *argv[])
{
	assert (MD_HEXLEN == 8*CTX_DHEXLEN); /* digest is in 8 blocks */
	ctx_t ctx;
	memset (&ctx, 0, sizeof (ctx_t));
  assert (sizeof (ctx.h[0])*2 == CTX_DHEXLEN);
	
	CTX_INIT (&ctx);
#ifdef ENABLE_DEBUG
	printf ("Init:\n");
	dump_ctx (&ctx);
#endif
	
	if (argc == 1)
		usage (argv[0]);
	
	int opt;
	unsigned long long msg_l = 0, step = DEFAULT_STEP,
		min_l = DEFAULT_MIN_MSG_L, max_l = DEFAULT_MAX_MSG_L;
	char *msg = NULL, *buf = NULL;
	char opts_seen[128] = {0};
	while ( (opt = getopt (argc, argv, "s:l:L:m:d:h")) != -1 )
	{
		if (opts_seen[opt])
		{
			fprintf (stderr, "Duplicate option\n");
			exit (EXIT_FAILURE);
		}
		opts_seen[opt] = 1;
		
		switch (opt)
		{
			case 'm':
				msg_l = strlen (optarg);
				msg = (char*)malloc (msg_l+1);
				if (msg == NULL)
				{
					perror ("");
					exit (EXIT_FAILURE);
				}
				snprintf (msg, msg_l+1, "%s", optarg);
				break;
			case 'd':
				if (set_ctx_md (&ctx, optarg) == -1)
					exit (EXIT_FAILURE);
				break;
			case 's':
			case 'l':
			case 'L':
				if (opt == 'l')
					min_l = strtoll (optarg, &buf, 10);
				else if (opt == 'L')
					max_l = strtoll (optarg, &buf, 10);
				else
					step = strtoll (optarg, &buf, 10);
				if (strlen (buf))
					usage (argv[0]);
				break;
			case 'h':
			case '?':
				usage (argv[0]);
				break;
			default:
				/* forgot to handle an option */
				assert (0);
		}
	}
	if (! opts_seen[(int)'m'])
	{
		fprintf (stderr, "Message is required\n");
		exit (EXIT_FAILURE);
	}
	if (! opts_seen[(int)'d'])
	{
		fprintf (stderr, "Initial digest is required\n");
		exit (EXIT_FAILURE);
	}
	assert (msg != NULL);
	
	/* Initial length and padding. */
	ssize_t npads = CBLOCK_AVAIL_LEN - (min_l % CBLOCK_LEN);
	if (npads < 0)
		npads += CBLOCK_LEN;
	assert (npads >= 0 && npads < CBLOCK_LEN);
	
	/* npads is no. of zeroes, CBLOCK_LEN - CBLOCK_AVAIL_LEN is 1 + no.
	 * of bytes for length */
	unsigned long long lpadded = min_l + npads + CBLOCK_LEN - CBLOCK_AVAIL_LEN;
	assert (lpadded % CBLOCK_LEN == 0);
	ctx.Nl = ((lpadded << 3) & CTX_LMASK);
	ctx.Nh = (lpadded >> (CTX_DLEN - 3));
	CTX_UPDATE (&ctx, msg, strlen (msg));
	
	ctx_t ctxtmp;
	memcpy (&ctxtmp, &ctx, sizeof (ctx_t));
	unsigned char md[MD_LEN] = {0};
	CTX_FINAL (md, &ctxtmp);
	printf ("digest:\t");
	print_md (md);
	
	for (unsigned long long l = min_l; l <= max_l; l += step)
	{
		/* Print padding */
		printf ("%5llu\t\\x80", l);
#ifdef ENABLE_DEBUG
		printf (" + \\x00 x %lu + ", npads);
#else
		for (size_t i = 0; i < (size_t)npads; i++)
			printf ("\\x00");
#endif
		/* length in big-endian */
		unsigned long long Nl = ((l << 3) & CTX_LMASK);
		unsigned long long Nh = (l >> (CTX_DLEN - 3));
		for (int s = (CTX_DLEN - 8); s >=0; s -= 8)
			printf ("\\x%02x", (unsigned char)((Nh >> s) & 0xFF));
		for (int s = (CTX_DLEN - 8); s >=0; s -= 8)
			printf ("\\x%02x", (unsigned char)((Nl >> s) & 0xFF));
		printf ("\n");
		
		npads -= step;
		while (npads < 0)
		{
			npads += CBLOCK_LEN;
			ctx.Nl += (CBLOCK_LEN << 3);
			if(ctx.Nl < (CBLOCK_LEN << 3))
				ctx.Nh++; /* wrapped around */
			if (npads < 0)
				continue;
			memcpy (&ctxtmp, &ctx, sizeof (ctx_t));
			unsigned char md[MD_LEN] = {0};
			CTX_FINAL (md, &ctxtmp);
			printf ("digest:\t");
			print_md (md);
		}
	}

	exit (EXIT_SUCCESS);
}

static int
hexchar2num (char c)
{
	if (c > 47 && c < 58)
		return (c - 48); /* ASCII 0 to 9 */
	if (c > 64 && c < 71)
		return (c - 55); /* ASCII A to F */
	if (c > 96 && c < 103)
		return (c - 87); /* ASCII a to f */
	return -1;
}

static int
set_ctx_md (ctx_t* ctx, const char* hex)
{
	if (strlen (hex) != MD_HEXLEN)
	{
		fprintf (stderr, "Wrong digest length %lu. "
			"Using digest length of %d\n", strlen (hex), MD_HEXLEN);
		return -1;
	}
	
	memset (ctx->h, 0, sizeof (ctx->h));
	size_t id = 0;
	for (size_t i = 0; i < MD_HEXLEN; i++)
	{
		if (i % CTX_DHEXLEN == 0 && i > 0)
		{
#ifdef ENABLE_DEBUG
			printf ("digest[%lu]: 0x" CTX_DFMT "\n", id, ctx->h[id]);
#endif
			id++;
		}

		int rc = hexchar2num (hex[i]);
		if (rc == -1)
		{
      printf ("Invalid character: %c\n", hex[i]);
			return -1;
		}
		ctx->h[id] |= ((uint64_t)rc) << 4*((MD_HEXLEN-i-1) % CTX_DHEXLEN);
		assert (id < 8);
	}
#ifdef ENABLE_DEBUG
		printf ("digest[%lu]: 0x" CTX_DFMT "\n", id, ctx->h[id]);
#endif
	return 0;
}

static void
print_md (const unsigned char* md)
{
	for (size_t i = 0; i < MD_LEN; i++)
		printf ("%02x", md[i]);
	printf ("\n");
}

/*************************************************************
 *                           DEBUG
 *************************************************************/

static void
dump_buf (void* buf_, uint32_t len)
{
	const unsigned char* buf = (const unsigned char*) buf_;
	char tmp[ 4*DUMP_ROW_LEN + DUMP_OFF_LEN + 2 + 1 ] = {0};

	for (uint32_t r = 0; r < len; r += DUMP_ROW_LEN) {
		sprintf (tmp, "%0*x: ", DUMP_OFF_LEN, r);

		/* hexdump */
		for (uint32_t b = 0; b < DUMP_ROW_LEN && b+r < len; b++)
			sprintf (tmp + DUMP_OFF_LEN + 2 + 3*b, "%02x ",
				(uint8_t)(buf[b+r]));

		/* ASCII dump */
		for (uint32_t b = 0; b < DUMP_ROW_LEN && b+r < len; b++)
			sprintf (tmp + DUMP_OFF_LEN + 2 + b + 3*DUMP_ROW_LEN,
				"%c", isprint (buf[b+r]) ? buf[b+r] : '.');

		printf ("%s\n", tmp);
	}
	printf ("\n");
}

static void
dump_ctx (ctx_t* ctx)
{
	printf (
    "  Nl:     0x" CTX_DFMT "\n"
    "  Nh:     0x" CTX_DFMT "\n"
    "  num:    %d\n"
    "  md_len: %d\n",
    ctx->Nl,
    ctx->Nh,
    ctx->num,
    ctx->md_len);
	for (int i = 0; i < 8; i++)
		printf (
			"  h%02d:    0x" CTX_DFMT "\n", i, ctx->h[i]);
#ifdef USE_SHA256
	dump_buf (ctx->data, CBLOCK_LEN);
#else
	dump_buf (ctx->u.p, CBLOCK_LEN);
#endif
	printf ("\n");
}
