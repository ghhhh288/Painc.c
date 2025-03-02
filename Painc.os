// DISCLAIMER:
// This code is provided for educational and experimental purposes only.
// Any unauthorized use, reproduction, distribution, or misappropriation of this 
// code is strictly prohibited without explicit written permission from the author.
// 
// By using this code, you assume all risks associated with its testing and deployment.
// The author shall not be liable for any direct, indirect, incidental, or consequential damages
// resulting from the use or misuse of this code.
// 
// Any attempt to steal, modify without attribution, or redistribute this code in violation 
// of these terms may result in legal action.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#define DEFAULT_SYSRQ_PATH "/proc/sysrq-trigger"

void print_usage(const char *progname) {
    printf("Usage: %s [-c command] [--simulate]\n", progname);
    printf("  -c command   Specify the sysrq command to trigger (default: 'c').\n");
    printf("  --simulate   Dry-run mode. No kernel panic is triggered.\n");
    printf("  -h, --help   Display this help message.\n");
}

int main(int argc, char *argv[]) {
    const char *sysrq_path = DEFAULT_SYSRQ_PATH;
    char command = 'c';
    int simulate = 0;

    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"simulate", no_argument, 0, 0},
        {"help",     no_argument, 0, 'h'},
        {0,          0,           0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp("simulate", long_options[option_index].name) == 0) {
                    simulate = 1;
                }
                break;
            case 'c':
                command = optarg[0];
                break;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            case '?':
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Warning: This program should be run as root to trigger a kernel panic.\n");
        if (!simulate) {
            return EXIT_FAILURE;
        }
    }

    fprintf(stdout, "Sysrq command to be triggered: '%c'\n", command);
    if (simulate) {
        fprintf(stdout, "Simulation mode enabled. No action taken.\n");
        return EXIT_SUCCESS;
    }

    int fd = open(sysrq_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", sysrq_path, strerror(errno));
        return EXIT_FAILURE;
    }

    ssize_t written = write(fd, &command, 1);
    if (written != 1) {
        fprintf(stderr, "Failed to trigger sysrq command '%c': %s\n", command, strerror(errno));
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);
    return EXIT_SUCCESS;
}
