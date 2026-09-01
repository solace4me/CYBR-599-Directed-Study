#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int call_bpf(enum bpf_cmd command, union bpf_attr *attributes)
{
    return (int)syscall(__NR_bpf, command, attributes, sizeof(*attributes));
}

static int open_pinned_map(const char *path)
{
    union bpf_attr attributes;

    memset(&attributes, 0, sizeof(attributes));
    attributes.pathname = (uint64_t)(uintptr_t)path;
    return call_bpf(BPF_OBJ_GET, &attributes);
}

static int print_map_identity(int map_fd)
{
    union bpf_attr attributes;
    struct bpf_map_info info;
    char name[BPF_OBJ_NAME_LEN + 1];

    memset(&attributes, 0, sizeof(attributes));
    memset(&info, 0, sizeof(info));
    attributes.info.bpf_fd = map_fd;
    attributes.info.info_len = sizeof(info);
    attributes.info.info = (uint64_t)(uintptr_t)&info;

    if (call_bpf(BPF_OBJ_GET_INFO_BY_FD, &attributes) != 0) {
        fprintf(stderr, "BPF_OBJ_GET_INFO_BY_FD failed: %s\n", strerror(errno));
        return -1;
    }

    memcpy(name, info.name, BPF_OBJ_NAME_LEN);
    name[BPF_OBJ_NAME_LEN] = '\0';
    printf(
        "TEST_PROCESS PID=%ld TID=%ld MAP_FD=%d MAP_ID=%u "
        "MAP_NAME=%s MAP_TYPE=%u\n",
        (long)getpid(),
        (long)syscall(SYS_gettid),
        map_fd,
        info.id,
        name[0] ? name : "unknown",
        info.type
    );
    fflush(stdout);
    return 0;
}

static int update_map(int map_fd, uint32_t key, uint32_t value)
{
    union bpf_attr attributes;

    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = map_fd;
    attributes.key = (uint64_t)(uintptr_t)&key;
    attributes.value = (uint64_t)(uintptr_t)&value;
    attributes.flags = BPF_ANY;
    return call_bpf(BPF_MAP_UPDATE_ELEM, &attributes);
}

static int delete_map_element(int map_fd, uint32_t key)
{
    union bpf_attr attributes;

    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = map_fd;
    attributes.key = (uint64_t)(uintptr_t)&key;
    return call_bpf(BPF_MAP_DELETE_ELEM, &attributes);
}

static int freeze_map(int map_fd)
{
    union bpf_attr attributes;

    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = map_fd;
    return call_bpf(BPF_MAP_FREEZE, &attributes);
}

static void print_usage(const char *program)
{
    fprintf(
        stderr,
        "Usage:\n"
        "  %s PINNED_MAP update KEY VALUE\n"
        "  %s PINNED_MAP delete KEY\n"
        "  %s PINNED_MAP freeze\n",
        program,
        program,
        program
    );
}

int main(int argc, char **argv)
{
    const char *path;
    const char *operation;
    uint32_t key = 0;
    uint32_t value = 0;
    int map_fd;
    int result;

    if (argc < 3) {
        print_usage(argv[0]);
        return 2;
    }

    path = argv[1];
    operation = argv[2];
    map_fd = open_pinned_map(path);
    if (map_fd < 0) {
        fprintf(stderr, "BPF_OBJ_GET failed for %s: %s\n", path, strerror(errno));
        return 1;
    }

    if (print_map_identity(map_fd) != 0) {
        close(map_fd);
        return 1;
    }

    if (strcmp(operation, "update") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            close(map_fd);
            return 2;
        }
        key = (uint32_t)strtoul(argv[3], NULL, 0);
        value = (uint32_t)strtoul(argv[4], NULL, 0);
        result = update_map(map_fd, key, value);
    } else if (strcmp(operation, "delete") == 0) {
        if (argc != 4) {
            print_usage(argv[0]);
            close(map_fd);
            return 2;
        }
        key = (uint32_t)strtoul(argv[3], NULL, 0);
        result = delete_map_element(map_fd, key);
    } else if (strcmp(operation, "freeze") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            close(map_fd);
            return 2;
        }
        result = freeze_map(map_fd);
    } else {
        print_usage(argv[0]);
        close(map_fd);
        return 2;
    }

    if (result == 0) {
        printf("OPERATION=%s RESULT=success\n", operation);
    } else {
        fprintf(stderr, "OPERATION=%s RESULT=failed ERROR=%s\n", operation, strerror(errno));
    }
    fflush(stdout);
    fflush(stderr);

    /* Keep the FD open long enough for Sentinel to resolve /proc/PID/fdinfo/FD. */
    sleep(3);
    close(map_fd);
    return result == 0 ? 0 : 1;
}
