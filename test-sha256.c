#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include "sha256.c"

/* Deal with everything in terms of u64 rather than u8 */
#undef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE (32 / 8)

#define HASH(a, b, c, d) { _(a), _(b), _(c), _(d) }
#define _(x) cpu_to_be64(0x ## x ## ULL)

static const struct test {
    const char *msg;
    u64 hash[SHA256_DIGEST_SIZE];
} tests[] = {
    {
        "",
        HASH(e3b0c44298fc1c14, 9afbf4c8996fb924, 27ae41e4649b934c, a495991b7852b855),
    },
    {
        "a",
        HASH(ca978112ca1bbdca, fac231b39a23dc4d, a786eff8147c4e72, b9807785afee48bb),
    },
    {
        "abc",
        HASH(ba7816bf8f01cfea, 414140de5dae2223, b00361a396177a9c, b410ff61f20015ad),
    },
    {
        "The quick brown fox jumps over the lazy dog",
        HASH(d7a8fbb307d78094, 69ca9abcb0082e4f, 8d5651e46d3cdb76, 2d02d0bf37c9e592),
    },
    {
        "                                        ", /* 40 */
        HASH(7ea876d646ae9ac0, dc26b5dade35c8ca, 70498aaef0464db2, 247d0afbe823d62d),
    },
    {
        "                                                  ", /* 50 */
        HASH(4c38d6d8bd1c5a30, 61e0c20067679faa, 28868831d7b83880, 0e3b64729af34354),
    },
    {
        "                                                            ", /* 60 */
        HASH(6a9c3911d69fdb86, d4b5a6b93dbdd9d5, d3b1125551416b7a, f129b29936ae48e2),
    },
    {
        "                                                                      ", /* 70 */
        HASH(f5d88515972d5d9b, df69f17f5cfde6d0, 33357f359c155efb, df18ca64a6dd6335),
    },
};

static void dump_hash(const u64 *hash)
{
    for ( unsigned int j = 0; j < SHA256_DIGEST_SIZE; ++j )
        printf("%016"PRIx64, cpu_to_be64(hash[j]));
}

int main(void)
{
    bool fail = false;

    for ( unsigned int i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        u64 hash[SHA256_DIGEST_SIZE];

        sha256sum((void *)hash, t->msg, strlen(t->msg));

        if ( memcmp(hash, t->hash, sizeof(hash)) == 0 )
            continue;

        fail = true;
        printf("Fail: Message '%s'\n"
               "  Got:      ",
               t->msg);

        dump_hash(hash);

        printf("\n"
               "  Expected: ");

        dump_hash(t->hash);
        printf("\n");
    }

    if ( !fail )
        printf("All ok\n");

    return fail;
}
