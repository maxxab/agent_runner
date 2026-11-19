/* Closed inert preparer records. Decoding supplies DATA, never authority. */
#ifndef RNR_RUNTIME_STAGE0_RECORDS_H
#define RNR_RUNTIME_STAGE0_RECORDS_H
#include <stddef.h>
#include <stdint.h>

struct rnr_stage0_image_record {
    unsigned char root[32], salt[32];
    uint64_t data_blocks, hash_blocks;
};
struct rnr_stage0_installation {
    struct rnr_stage0_image_record runtime;
    unsigned char asset_root[32];
};
struct rnr_stage0_task {
    unsigned char task_id[16];
    int64_t wall_cutoff_ns;
    const unsigned char *payload;
    size_t payload_bytes;
};
struct rnr_stage0_output {
    unsigned char task_id[16];
    struct rnr_stage0_image_record launch;
};
/* Exact bytes only; return0 for valid structure or-1. Non-NULL output is
 * cleared on rejection. Input/output buffers must not overlap. Task payload
 * borrows caller bytes: caller must keep them unchanged/alive. JSON canonical
 * v3/schema/pin correlation is NOT checked here; the original Python consumer
 * must check it before downstream effects. No file/clock/Store/claim actions.
 * Protected reader/installer trust and original T0 remain separate mandatory
 * gates. Output records cannot instantiate or resume a live preparer.
 */
int rnr_stage0_decode_installation(const unsigned char *, size_t,
                                  struct rnr_stage0_installation *);
int rnr_stage0_decode_task(const unsigned char *, size_t, struct rnr_stage0_task *);
int rnr_stage0_decode_output(const unsigned char *, size_t, struct rnr_stage0_output *);
#endif
