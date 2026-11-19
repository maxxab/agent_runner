/* Explicit little-endian data decoders. Not a reader, installer or entry. */
#include "runtime_stage0_records.h"
#include <limits.h>
#include <string.h>

_Static_assert(CHAR_BIT == 8, "unsupported byte ABI");

static uint64_t little(const unsigned char *p, unsigned int n)
{
    uint64_t v = 0;
    for (unsigned int j = 0; j < n; ++j) v |= (uint64_t)p[j] << (8*j);
    return v;
}
static int all_zero(const unsigned char *p, size_t n)
{
    unsigned char v = 0;
    for (size_t j = 0; j < n; ++j) v |= p[j];
    return v == 0;
}
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    return av <= bv ? bv-av < an : av-bv < bn;
}
static int header(const unsigned char *p, const char *magic)
{
    return memcmp(p,magic,8)==0 && little(p+8,4)==1 && little(p+12,4)==0;
}
static int image(const unsigned char *root, const unsigned char *salt,
                 uint64_t data, uint64_t hashes, uint64_t maximum,
                 struct rnr_stage0_image_record *out)
{
    uint64_t level = data, total = 0;
    if (all_zero(root,32) || all_zero(salt,32) || data < 2 || data > maximum)
        return -1;
    do {
        level = (level + 127) / 128;
        total += level;
    } while (level > 1);
    if (hashes != total) return -1;
    memcpy(out->root,root,32); memcpy(out->salt,salt,32);
    out->data_blocks = data; out->hash_blocks = hashes;
    return 0;
}
int rnr_stage0_decode_installation(const unsigned char *raw, size_t bytes,
                                  struct rnr_stage0_installation *out)
{
    struct rnr_stage0_installation value = {0};
    if (out == NULL) return -1;
    /* Reject overlap before clearing can destroy any bytes to be decoded. */
    int alias = raw != NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if (raw == NULL || bytes != 128 || alias || !header(raw,"RNRI0001") ||
        all_zero(raw+96,32) ||
        image(raw+16,raw+48,little(raw+80,8),little(raw+88,8),131072,&value.runtime)!=0)
        return -1;
    memcpy(value.asset_root,raw+96,32);
    *out = value;
    return 0;
}
int rnr_stage0_decode_task(const unsigned char *raw, size_t bytes, struct rnr_stage0_task *out)
{
    struct rnr_stage0_task value = {0};
    if (out == NULL) return -1;
    int alias = raw != NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if (raw == NULL || bytes < 65 || bytes > 65600 || alias ||
        !header(raw,"RNRT0001") || all_zero(raw+16,16) || !all_zero(raw+44,20))
        return -1;
    uint64_t cutoff = little(raw+32,8), count = little(raw+40,4);
    if (cutoff == 0 || cutoff > INT64_MAX || count == 0 || count > 65536 ||
        count != bytes-64) return -1;
    memcpy(value.task_id,raw+16,16);
    value.wall_cutoff_ns = (int64_t)cutoff;
    value.payload = raw+64; value.payload_bytes = (size_t)count;
    *out = value;
    return 0;
}
int rnr_stage0_decode_output(const unsigned char *raw, size_t bytes, struct rnr_stage0_output *out)
{
    struct rnr_stage0_output value = {0};
    if (out == NULL) return -1;
    int alias = raw != NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if (raw == NULL || bytes != 128 || alias || !header(raw,"RNRP0001") ||
        all_zero(raw+16,16) || !all_zero(raw+112,16) ||
        image(raw+32,raw+64,little(raw+96,8),little(raw+104,8),1024,&value.launch)!=0)
        return -1;
    memcpy(value.task_id,raw+16,16);
    *out = value;
    return 0;
}
