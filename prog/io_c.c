#include <stdio.h>
#include <pthread.h>

#define STRING_SIZE 10000000
char big_string[STRING_SIZE];

void *write_file(void *vargp) {
    int id = *(int*)vargp;

    FILE *fp;
    char fname[20];
    sprintf(fname, "out/%d.txt", id);
    fp = fopen(fname, "w");

    fputs(big_string, fp);
    fputs("end", fp);

    fclose(fp);
    return NULL;
}

int main() {
    char letters[] = "abcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < STRING_SIZE; i++) {
        big_string[i] = letters[i % 26];
    }

    pthread_t thread_id;

    for (int i = 0; i < 64; i++) {
        pthread_create(&thread_id, NULL, write_file, (void *) &i);
    }

    pthread_exit(NULL);

    return 0;
}

