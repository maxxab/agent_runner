/* Dormant native structural FD admission, NOT the authenticated stage0.
 * No main, exec, fork, Store, mount, device or daemon operation.
 * Uncompiled/unexecuted until separately authorized; see private evidence.
 */
#define _GNU_SOURCE
#include "runtime_stage0_admission.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(SYS_getdents64)
#error "Initial FD admission supports Linux x86_64 getdents64 only"
#endif
_Static_assert(CHAR_BIT == 8 && sizeof(long) == 8 && sizeof(int) == 4, "unsupported Linux ABI");

enum { INPUTS = 9, ENTRIES = 10, RECORDS = 12, READS = 13, BUFFER_BYTES = 4096 };
/* Linux getdents64: ino64[0:8], off64[8:16], reclen16[16:18],
 * type8[18], name[19:]. Never cast potentially unaligned record memory.
 */
enum { NAME_OFFSET = 19, RECLEN_OFFSET = 16 };

static void reject(struct rnr_stage0_admission_error *error,
                   enum rnr_stage0_admission_code code, int system_errno)
{
    if (error->code == RNR_STAGE0_ADMISSION_OK) {
        error->code = code;
        error->system_errno = system_errno;
    }
}

static int same_identity(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_rdev == b->st_rdev;
}

static int fd_number(const unsigned char *name, size_t length, int *result)
{
    unsigned int value = 0;
    if (length == 0 || length > 10 || (length > 1 && name[0] == '0'))
        return -1;
    for (size_t i = 0; i < length; ++i) {
        unsigned int digit;
        if (name[i] < '0' || name[i] > '9')
            return -1;
        digit = (unsigned int)(name[i] - '0');
        if (value > ((unsigned int)INT_MAX - digit) / 10)
            return -1;
        value = value * 10 + digit;
    }
    *result = (int)value;
    return 0;
}

/* Only the two fixed wrappers below select a profile. No caller whitelist. */
static int admit_fds(struct rnr_stage0_admission_error *error, int inputs_count)
{
    struct stat inputs[INPUTS], held, current, null_device;
    unsigned char buffer[BUFFER_BYTES];
    unsigned char seen[ENTRIES] = {0};
    unsigned int records = 0, numbers = 0, dots = 0;
    const int entries_count = inputs_count + 1;
    const unsigned int record_limit = (unsigned int)entries_count + 2;
    const unsigned int read_limit = record_limit + 1;
    int directory = -1, eof = 0;

    if (error == NULL) {
        errno = EINVAL;
        return -1;
    }
    *error = (struct rnr_stage0_admission_error){RNR_STAGE0_ADMISSION_OK, 0, 0};
    for (int fd = 0; fd < inputs_count; ++fd) {
        if (fstat(fd, &inputs[fd]) != 0) {
            reject(error, RNR_STAGE0_ADMISSION_INPUT, errno);
            goto cleanup;
        }
    }
    if (stat("/dev/null", &null_device) != 0) {
        reject(error, RNR_STAGE0_ADMISSION_STDIO, errno);
        goto cleanup;
    }
    if (!S_ISCHR(null_device.st_mode)) {
        reject(error, RNR_STAGE0_ADMISSION_STDIO, 0);
        goto cleanup;
    }
    for (int fd = 0; fd < 3; ++fd) {
        int flags = fcntl(fd, F_GETFL);
        int access;
        mode_t mode = inputs[fd].st_mode;
        if (flags < 0) {
            reject(error, RNR_STAGE0_ADMISSION_STDIO, errno);
            goto cleanup;
        }
        access = flags & O_ACCMODE;
        if ((flags & O_PATH) ||
            (fd == 0 ? access != O_RDONLY && access != O_RDWR :
                       access != O_WRONLY && access != O_RDWR) ||
            !(S_ISREG(mode) || S_ISFIFO(mode) ||
              (S_ISCHR(mode) && inputs[fd].st_rdev == null_device.st_rdev))) {
            reject(error, RNR_STAGE0_ADMISSION_STDIO, 0);
            goto cleanup;
        }
    }

    directory = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        reject(error, RNR_STAGE0_ADMISSION_OPEN, errno);
        goto cleanup;
    }
    if (directory < inputs_count) {
        reject(error, RNR_STAGE0_ADMISSION_DIRECTORY, 0);
        goto cleanup;
    }
    if (fstat(directory, &held) != 0) {
        reject(error, RNR_STAGE0_ADMISSION_DIRECTORY, errno);
        goto cleanup;
    }
    if (!S_ISDIR(held.st_mode)) {
        reject(error, RNR_STAGE0_ADMISSION_DIRECTORY, 0);
        goto cleanup;
    }

    for (unsigned int reads = 0; reads < read_limit; ++reads) {
        long received = syscall(SYS_getdents64, directory, buffer, sizeof(buffer));
        size_t offset = 0;
        if (received < 0) {
            reject(error, RNR_STAGE0_ADMISSION_READ, errno);
            goto cleanup; /* EINTR is rejection, not a retry/renewal. */
        }
        if (received == 0) {
            eof = 1;
            break;
        }
        if (received > BUFFER_BYTES) {
            reject(error, RNR_STAGE0_ADMISSION_RECORD, 0);
            goto cleanup;
        }
        while (offset < (size_t)received) {
            uint16_t record_length;
            const unsigned char *name, *end;
            size_t length, remaining = (size_t)received - offset;
            int fd, index;
            if (++records > record_limit || remaining <= NAME_OFFSET) {
                reject(error, RNR_STAGE0_ADMISSION_RECORD, 0);
                goto cleanup;
            }
            memcpy(&record_length, buffer + offset + RECLEN_OFFSET, sizeof(record_length));
            if (record_length <= NAME_OFFSET || record_length % 8 != 0 ||
                record_length > remaining) {
                reject(error, RNR_STAGE0_ADMISSION_RECORD, 0);
                goto cleanup;
            }
            name = buffer + offset + NAME_OFFSET;
            end = memchr(name, 0, record_length - NAME_OFFSET);
            if (end == NULL) {
                reject(error, RNR_STAGE0_ADMISSION_RECORD, 0);
                goto cleanup;
            }
            length = (size_t)(end - name);
            offset += record_length;
            if ((length == 1 && name[0] == '.') ||
                (length == 2 && name[0] == '.' && name[1] == '.')) {
                unsigned int bit = length == 1 ? 1U : 2U;
                if (dots & bit) {
                    reject(error, RNR_STAGE0_ADMISSION_RECORD, 0);
                    goto cleanup;
                }
                dots |= bit;
                continue;
            }
            if (fd_number(name, length, &fd) != 0) {
                reject(error, RNR_STAGE0_ADMISSION_RECORD, 0);
                goto cleanup;
            }
            index = fd < inputs_count ? fd : (fd == directory ? inputs_count : -1);
            if (index < 0 || seen[index] || ++numbers > (unsigned int)entries_count) {
                reject(error, RNR_STAGE0_ADMISSION_INVENTORY, 0);
                goto cleanup;
            }
            seen[index] = 1;
            if (fstat(fd, &current) != 0) {
                reject(error, RNR_STAGE0_ADMISSION_IDENTITY, errno);
                goto cleanup;
            }
            if (!same_identity(&current, index < inputs_count ? &inputs[index] : &held)) {
                reject(error, RNR_STAGE0_ADMISSION_IDENTITY, 0);
                goto cleanup;
            }
        }
    }
    if (!eof || numbers != (unsigned int)entries_count) {
        reject(error, RNR_STAGE0_ADMISSION_INVENTORY, 0);
        goto cleanup;
    }
    for (int index = 0; index < entries_count; ++index) {
        int fd = index < inputs_count ? index : directory;
        if (!seen[index]) {
            reject(error, RNR_STAGE0_ADMISSION_INVENTORY, 0);
            goto cleanup;
        }
        if (fstat(fd, &current) != 0) {
            reject(error, RNR_STAGE0_ADMISSION_IDENTITY, errno);
            goto cleanup;
        }
        if (!same_identity(&current, index < inputs_count ? &inputs[index] : &held)) {
            reject(error, RNR_STAGE0_ADMISSION_IDENTITY, 0);
            goto cleanup;
        }
    }

cleanup:
    if (directory >= 0) {
        int owned = directory;
        directory = -1; /* invalidate before exactly one close, even on EINTR */
        if (close(owned) != 0) {
            int failure = errno;
            error->cleanup_errno = failure;
            reject(error, RNR_STAGE0_ADMISSION_CLEANUP, failure);
        }
    }
    return error->code == RNR_STAGE0_ADMISSION_OK ? 0 : -1;
}

int rnr_stage0_admit_initial_fds(struct rnr_stage0_admission_error *error)
{
    return admit_fds(error, 9);
}

int rnr_stage0_admit_preparation_fds(struct rnr_stage0_admission_error *error)
{
    return admit_fds(error, 3);
}
