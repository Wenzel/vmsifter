#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

// declare getopt short / long options
static const char* OPTS = "hDS:m:p:";
static const struct option LONG_OPTS[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"debug", no_argument, NULL, 'D'},
        {"socket", required_argument, NULL, 'S'},
        {"insn-buf-size", required_argument, NULL, 'm'},
        {"pin-cpu", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };
// default config
static bool debug = false;
static uint32_t pinned_cpu = 0;
static char* sock = NULL;
static uint16_t insn_buf_size = 15;

// msg structs
enum regs {
    _RIP,
    _RAX,
    _RBX,
    _RCX,
    _RDX,
    _RSI,
    _RDI,
    _RSP,
    _RBP,
    _R8,
    _R9,
    _R10,
    _R11,
    _R12,
    _R13,
    _R14,
    _R15,
    _CR2,
    NUMBER_OF_REGISTERS
};
#define NUMBER_OF_PERF_COUNTERS 7

struct __attribute__ ((__packed__)) InjectorInputMessage {
    // flexible array members cannot be declared in otherwise empty structs
    uint32_t insn_size;
    uint8_t insn[];
};

struct __attribute__ ((__packed__)) InjectorResultMessage {
    uint64_t reason;
    uint64_t qualification;
    uint64_t stack_value;
    uint64_t perfct[NUMBER_OF_PERF_COUNTERS];
    uint64_t regs[NUMBER_OF_REGISTERS];
    uint64_t gla;
    uint32_t intr_info;
    uint32_t intr_error;
    uint32_t vec_info;
    uint32_t vec_error;
    uint32_t insn_size;
    uint32_t insn_info;
};

static void help(void)
{
    // TODO
}

static bool validate_args(void)
{
    if (!sock) {
        fprintf(stderr, "socket is required\n");
        return false;
    }
    return true;
}

static bool send_next_res(int sockfd, struct InjectorResultMessage* res)
{
    unsigned int sent_count = send(sockfd, res, sizeof(struct InjectorResultMessage), 0);
    if ( sent_count != sizeof(struct InjectorResultMessage) )
    {
        perror("send");
        return false;
    }
    return true;
}

static bool recv_next_msg(int sockfd, struct InjectorInputMessage* msg)
{
    ssize_t res = recv(sockfd, msg->insn, insn_buf_size, 0);
    if (res < 0) {
        // connection closed
        perror("recv");
        return false;
    }
    else if (!res) {
        // EOF
        fprintf(stderr, "Received EOF: socket closed\n");
        return false;
    }
    msg->insn_size = res;
    return true;
}

static bool init_socket(const char* sock_path, int* sockfd)
{
    // create Unix socket
    if (((*sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)) {
        perror("socket");
        return false;
    }

    // set server address
    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, sock_path, sizeof(server_addr.sun_path) - 1);
    socklen_t server_addr_len = sizeof(server_addr);

    // connect to server
    if (connect(*sockfd, (struct sockaddr*)&server_addr, server_addr_len) == -1) {
        perror("connect");
        return false;
    }

    // "handshake"
    // just send first injectResult to validate size
    struct InjectorResultMessage msg = {0};
    if (!send_next_res(*sockfd, &msg)) {
        return false;
    }

    return true;
}

static bool inject_insn(struct InjectorInputMessage* input_insn, struct InjectorResultMessage* res)
{
    // just print current insn
    if (debug) {
        for (unsigned int i=0; i<input_insn->insn_size;i++)
            printf("%.2x ", input_insn->insn[i]);
        printf("\n");
    }

    uintptr_t* p = (uintptr_t*)res;
    // fill garbage into res
    for (size_t i = 0; i < sizeof(struct InjectorResultMessage); i++) {
        p[i] = rand() % 256;
    }
    return true;
}

static void communicate(int sockfd, struct InjectorInputMessage* input_insn, struct InjectorResultMessage* res)
{
    // get next insn
    if (!recv_next_msg(sockfd, input_insn)) {
        fprintf(stderr, "Failed to receive next insn\n");
        exit(1);
    }

    // handle insn
    if (!inject_insn(input_insn, res)) {
        fprintf(stderr, "Failed to inject insn\n");
        exit(1);
    }

    // send next msg
    if (!send_next_res(sockfd, res)) {
        fprintf(stderr, "Failed to send result\n");
        exit(1);
    }
}


int main(int argc, char** argv)
{
    // parse args with getopts
    int c, long_index = 0;
    while ((c = getopt_long (argc, argv, OPTS, LONG_OPTS, &long_index)) != -1)
    {
        switch(c)
        {
        case 'h':
            help();
            return 0;
        case 'D':
            debug = 1;
            break;
        case 'S':
            sock = optarg;
            break;
            pinned_cpu = atoi(optarg);
            break;
        case 'm':
            insn_buf_size = atoi(optarg);
            break;
        default:
            break;
        }
    }

    // validate them
    if (!validate_args())
        return 1;

    // connect to provided Unix socket
    int sockfd = 0;
    if (!init_socket(sock, &sockfd))
        return 1;

    // init random seed
    srand(time(NULL));

    struct InjectorInputMessage* input_insn = calloc(1, sizeof(struct InjectorInputMessage) + insn_buf_size);
    struct InjectorResultMessage res = {0};
    while (true) {
        communicate(sockfd, input_insn, &res);
    }
    free(input_insn);
}
