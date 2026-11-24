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
    /* In-process decoded data, NOT a stable serialized ABI. Rebuild every
     * consumer after changing this structure. v1 leaves extensions zero. */
    uint32_t version;
    unsigned char project_id[32], store_instance[16];
    uint64_t store_device, store_inode;
    uint32_t filesystem_id[2];
    char boot_id[37];
    unsigned char configuration_digest[32], enrollment_digest[32];
    unsigned char startup_digest[32], execution_root[32], unit_policy_digest[32];
};
/* Borrowed ASCII views require the original immutable payload to stay alive. */
struct rnr_stage0_text_view { const unsigned char *bytes; size_t length; };
struct rnr_stage0_launch_file { unsigned char digest[32]; uint64_t bytes; };
struct rnr_stage0_launch_declaration {
    uint32_t version;
    unsigned char allocation[16], asset_root[32], execution_root[32];
    unsigned char tool_digest[32], manager_digest[32], daemon_digest[32];
    int64_t positive_wall_ns;
    uint64_t run_capacity, run_commands, run_turn_capacity, run_turns, queue_bound;
    uint64_t input_bytes, item_text_bytes, turn_items;
    uint64_t runtime_slots, reviewer_reserve, workload_slots;
    uint64_t cpu_millis, memory_bytes, output_bytes, pids, scratch_bytes, swap_bytes;
    struct rnr_stage0_text_view model, effort, run_id, supervisor_epoch;
    struct rnr_stage0_launch_file files[7];
    struct rnr_stage0_text_view unit_paths[32];
    size_t unit_path_count;
};
/* DATA-only canonical v3 subset: unescaped printable ASCII strings and
 * nonnegative signed64 integers. Closed schema/value checks, no origin/host/
 * installation correlation, authentication or effect. Retain raw immutable
 * bytes for all borrowed views. Exact rules in persistent-admission-contract.
 * Reject overlap against the entire output and fail-clear on all rejection. */
int rnr_stage0_decode_launch_declaration(const unsigned char *, size_t,
                                        struct rnr_stage0_launch_declaration *);
/* Candidate F exact binary policy DATA. No protected-file provenance, hash,
 * owner approval, kernel limits or correlation is established by decoding.
 * Text views borrow unchanged caller bytes, just like launch declarations. */
struct rnr_stage0_policy_unit {
    unsigned char fragment_digest[32];
    uint64_t cpu_millis, memory_bytes, swap_bytes, pids, cpu_period_us;
};
struct rnr_stage0_policy {
    uint32_t version, flags;
    unsigned char project_id[32], store_instance[16];
    char boot_id[37];
    unsigned char configuration_digest[32], enrollment_digest[32], startup_digest[32];
    unsigned char native_digest[32], manager_digest[32], python_digest[32];
    unsigned char execution_root[32], asset_root[32], tool_digest[32], daemon_digest[32];
    unsigned char revision[32];
    size_t revision_bytes;
    struct rnr_stage0_text_view repository, host;
    uint64_t native_bytes, manager_bytes, python_bytes;
    uint32_t configuration_bytes, enrollment_bytes, startup_bytes;
    struct rnr_stage0_policy_unit units[4];
    struct rnr_stage0_text_view unit_paths[32];
    size_t unit_path_count;
};
/* Exact9728 bytes, fail-clear, no input/output overlap. Clearing an overlapping
 * output necessarily changes those input bytes. No runtime caller is enabled. */
int rnr_stage0_decode_policy(const unsigned char *, size_t, struct rnr_stage0_policy *);
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
/* Installation accepts exact inert v1/128 or v2/448 framing. The current
 * legacy input reader reads v1; held admission inputs require v2. v2 adds DATA,
 * never store identity
 * authentication, filesystem durability, reboot reconciliation or admission. */
int rnr_stage0_decode_installation(const unsigned char *, size_t,
                                  struct rnr_stage0_installation *);
int rnr_stage0_decode_task(const unsigned char *, size_t, struct rnr_stage0_task *);
int rnr_stage0_decode_output(const unsigned char *, size_t, struct rnr_stage0_output *);
#endif
