#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include "sha1sum.c"

/* Deal with everything in terms of u32 rather than u8 */
#undef SHA1_DIGEST_SIZE
#define SHA1_DIGEST_SIZE (20 / 4)

#define HASH(a, b, c, d, e) { _(a), _(b), _(c), _(d), _(e) }
#define _(x) cpu_to_be32(0x ## x)

static const struct test {
    const char *msg;
    u32 hash[SHA1_DIGEST_SIZE];
} tests[] = {
    {
        "",
        HASH(da39a3ee, 5e6b4b0d, 3255bfef, 95601890, afd80709),
    },
    {
        "a",
        HASH(86f7e437, faa5a7fc, e15d1ddc, b9eaeaea, 377667b8),
    },
    {
        "abc",
        HASH(a9993e36, 4706816a, ba3e2571, 7850c26c, 9cd0d89d),
    },
    {
        "The quick brown fox jumps over the lazy dog",
        HASH(2fd4e1c6, 7a2d28fc, ed849ee1, bb76e739, 1b93eb12),
    },
    {
        "                                        ", /* 40 */
        HASH(108a95c4, 27e99c98, ffec5980, f74ae18d, d7e6a6f1),
    },
    {
        "                                                  ", /* 50 */
        HASH(346729de, baf8c9e1, 042ae6e3, 82768fc2, c172c351),
    },
    {
        "                                                            ", /* 60 */
        HASH(3c82ec78, da97a701, 6b999152, 468f3488, 16c55e28),
    },
    {
        "                                                                      ", /* 70 */
        HASH(6f2a4b80, 7e4fd5ac, cdae059f, 9ec553b1, a6872a27),
    },
};

static void dump_hash(const u32 *hash)
{
    for ( unsigned int j = 0; j < SHA1_DIGEST_SIZE; ++j )
        printf("%08"PRIx32, cpu_to_be32(hash[j]));
}

int main(void)
{
    bool fail = false;

    for ( unsigned int i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        const struct test *t = &tests[i];
        u32 hash[SHA1_DIGEST_SIZE];

        sha1sum((void *)hash, t->msg, strlen(t->msg));

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
