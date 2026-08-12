#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TITLE_MAX 512
char flag[75] = {0};

// These functions are redacted on purpose

static int fetch_title(const char *host, char *out, size_t outlen)
{
    return 0;
}

static int validate_title(const char *title)
{
    return 1;
}

static int validate_host(const char *host)
{
    return 1;
}

// This is all the source you get...
static void fetching_animation(void)
{
    const char spin[] = "|/-\\";
    for (int i = 0; i < 30; i++) {
        printf("\rfetching... %c", spin[i % 4]);
        fflush(stdout);
        usleep(100000);
    }
    printf("\r                    \r");
    fflush(stdout);
}

int main(void)
{
    char host[256];

    FILE *ff = fopen("REDACTED.txt", "r"); // you don't know the file name. Time for RCE right?
    fgets(flag, sizeof flag, ff);
    flag[strcspn(flag, "\r\n")] = '\0';
    fclose(ff);

    for (;;) {
        printf("enter host: ");
        fflush(stdout);
        if (!fgets(host, sizeof host, stdin)) {
            fprintf(stderr, "error\n");
            break;
        }
        host[strcspn(host, "\r\n")] = '\0';

        if (!validate_host(host)) {
            printf("hacking attempt detected\n");
            continue;
        }

        char title[TITLE_MAX];
        if (fetch_title(host, title, sizeof title) != 0) {
            fprintf(stderr, "error: could not fetch title\n");
            continue;
        }
        printf("validating title: %s\n", title);

        fetching_animation();

        if (!validate_title(title)) {
            printf("hacking attempt detected\n");
            continue;
        }
        printf("title secure\n");


        char fresh[TITLE_MAX];
        if (fetch_title(host, fresh, sizeof fresh) != 0) {
            fprintf(stderr, "error\n");
            continue;
        }

        printf("completed fetching: %s\n", fresh);
    }

    return 0;
}
