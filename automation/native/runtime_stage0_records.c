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
static int boot_uuid(const unsigned char *raw)
{
    int nonzero = 0;
    for (unsigned int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (raw[i] != '-') return -1;
        } else {
            if (!((raw[i] >= '0' && raw[i] <= '9') ||
                  (raw[i] >= 'a' && raw[i] <= 'f'))) return -1;
            if (raw[i] != '0') nonzero = 1;
        }
    }
    return nonzero ? 0 : -1;
}
int rnr_stage0_decode_installation(const unsigned char *raw, size_t bytes,
                                  struct rnr_stage0_installation *out)
{
    struct rnr_stage0_installation value = {0};
    if (out == NULL) return -1;
    /* Reject overlap before clearing can destroy any bytes to be decoded. */
    int alias = raw != NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if (raw == NULL || alias || (bytes != 128 && bytes != 448)) return -1;
    if (bytes == 128) {
        if (!header(raw,"RNRI0001")) return -1;
        value.version = 1;
    } else {
        if (memcmp(raw,"RNRI0002",8) != 0 || little(raw+8,4) != 2 ||
            little(raw+12,4) != 0 || !all_zero(raw+236,4) || !all_zero(raw+400,48) ||
            all_zero(raw+128,32) || all_zero(raw+160,16) || little(raw+184,8) == 0 ||
            boot_uuid(raw+200) != 0 || all_zero(raw+240,32) || all_zero(raw+272,32) ||
            all_zero(raw+304,32) || all_zero(raw+336,32) || all_zero(raw+368,32))
            return -1;
        value.version = 2;
        memcpy(value.project_id,raw+128,32);
        memcpy(value.store_instance,raw+160,16);
        value.store_device = little(raw+176,8);
        value.store_inode = little(raw+184,8);
        /* Explicit bit patterns; never cast host fsid_t or sign extend. */
        value.filesystem_id[0] = (uint32_t)little(raw+192,4);
        value.filesystem_id[1] = (uint32_t)little(raw+196,4);
        memcpy(value.boot_id,raw+200,36);
        memcpy(value.configuration_digest,raw+240,32);
        memcpy(value.enrollment_digest,raw+272,32);
        memcpy(value.startup_digest,raw+304,32);
        memcpy(value.execution_root,raw+336,32);
        memcpy(value.unit_policy_digest,raw+368,32);
    }
    if (all_zero(raw+96,32) ||
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
