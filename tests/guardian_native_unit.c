/* Offline native checks; never starts a namespace or application. */
#define main guardian_program_main
#define prctl test_prctl
#include "../automation/native/runtime_guardian.c"
#undef main
#undef prctl
#include <assert.h>
#include <sys/socket.h>

static int ambient_result;
int test_prctl(int option, ...) { (void)option; return ambient_result; }

int main(void) {
    int64_t value = 0;
    assert(parse_number("1", &value) && value == 1);
    assert(parse_number("9223372036854775807", &value) && value == INT64_MAX);
    const char *bad[] = {"", "0", "01", "-1", "+1", "1 ", "1x", "9223372036854775808"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++)
        assert(!parse_number(bad[i], &value));

    struct buffer wire = {0}, app = {0};
    uint64_t total = 0;
    assert(queue_frame(&wire, 'O', (const unsigned char *)"ab", 2, 3, &total));
    assert(wire.used == 7 && wire.bytes[0] == 'O' && wire.bytes[4] == 2 && total == 2);
    assert(!queue_frame(&wire, 'E', (const unsigned char *)"cd", 2, 3, &total));
    assert(total == 2 && wire.used == 7);
    wire.bytes[0] = 'I';
    assert(input_frame(&wire, &app) == 1 && wire.used == 0 && app.used == 2);
    assert(app.bytes[0] == 'a' && app.bytes[1] == 'b');
    assert(input_frame(&wire, &app) == 0);
    wire.bytes[0] = 'S'; wire.used = 1;
    assert(input_frame(&wire, &app) == -1);
    wire.bytes[0] = 'I'; wire.bytes[1] = 0; wire.bytes[2] = 1;
    wire.bytes[3] = 0; wire.bytes[4] = 1; wire.used = 5;
    assert(input_frame(&wire, &app) == -1);
    wire.bytes[2] = 0; wire.bytes[4] = 2;
    assert(input_frame(&wire, &app) == 0);
    wire.used = 7; app.used = BUFFER_SIZE - 1;
    assert(input_frame(&wire, &app) == -1);
    wire.used = BUFFER_SIZE - 1;
    assert(!queue_frame(&wire, 'S', (const unsigned char *)"ARMED", 5, 3, &total));
    wire.used = BUFFER_SIZE / 2; app.used = BUFFER_SIZE / 2;
    assert(input_room(&wire, &app) == 0);
    app.used--;
    assert(input_room(&wire, &app) == 1);
    assert(ambient_empty(40));
    ambient_result = -1; errno = EINVAL;
    assert(!ambient_empty(40));
    ambient_result = 1;
    assert(!ambient_empty(40));
    ambient_result = 0;
    assert(!ambient_empty(64));
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    assert(stream_fd(pipefd[0]) && stream_fd(pipefd[1]));
    assert(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    int nonstream = open("/dev/null", O_RDONLY);
    assert(nonstream >= 0 && !stream_fd(nonstream));
    assert(close(nonstream) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd) == 0);
    assert(stream_fd(pipefd[0]) && stream_fd(pipefd[1]));
    assert(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pipefd) == 0);
    assert(!stream_fd(pipefd[0]) && !stream_fd(pipefd[1]));
    assert(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    return 0;
}
