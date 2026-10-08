// aether_proof.c — ARM-tier userspace proof payload (installed as /bin/sh in
// the test initramfs; the hypervisor boots the guest with rdinit=/bin/sh).
//
// Runs at EL0 inside the Android-partition guest under AETHER's EL2 and prints
// machine-checkable PROOF lines for the chapter gates:
//   ch34  userspace reached        -> "PROOF ch34 userspace=1"
//   ch35  all vCPUs online         -> "PROOF ch35 online_cpus=N"
//   ch36  timer IRQs tick per CPU  -> "PROOF ch36 cpuK timer_delta=D" (D > 0)
//         IPIs delivered            -> "PROOF ch36 ipi_delta=D"
// then prints "PROOF done" and idles. Built static (no dynamic loader needed):
//   aarch64-linux-gcc -static -O2 -o sh aether_proof.c
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#define MAXCPU 16

// Sum per-CPU counts for /proc/interrupts lines whose label contains `needle`.
static int irq_counts(const char *needle, long out[MAXCPU]) {
    char buf[65536];
    int fd = open("/proc/interrupts", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    int ncpu = 0;
    char *line = strtok(buf, "\n");
    // Header: "           CPU0       CPU1 ..."
    for (char *p = line; (p = strstr(p, "CPU")); p += 3) ncpu++;
    memset(out, 0, sizeof(long) * MAXCPU);
    while ((line = strtok(NULL, "\n"))) {
        if (!strstr(line, needle)) continue;
        char *p = strchr(line, ':');
        if (!p) continue;
        p++;
        for (int c = 0; c < ncpu && c < MAXCPU; c++) out[c] += strtol(p, &p, 10);
    }
    return ncpu;
}

static void *spin(void *arg) {
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET((int)(long)arg, &s);
    sched_setaffinity(0, sizeof s, &s);
    volatile unsigned long x = 0;
    for (unsigned long i = 0; i < 20000000UL; i++) x += i;
    return NULL;
}

int main(void) {
    mkdir("/proc", 0555);
    mount("proc", "/proc", "proc", 0, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    struct utsname u;
    uname(&u);
    printf("\nPROOF ch34 userspace=1 kernel=%s machine=%s pid=%d\n", u.release, u.machine, getpid());

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    printf("PROOF ch35 online_cpus=%ld\n", ncpu);

    long t0[MAXCPU], t1[MAXCPU], i0[MAXCPU], i1[MAXCPU];
    int n = irq_counts("arch_timer", t0);
    irq_counts("IPI", i0);
    // Put work on every CPU (forces scheduler IPIs + per-CPU timer activity).
    pthread_t th[MAXCPU];
    for (long c = 0; c < ncpu && c < MAXCPU; c++) pthread_create(&th[c], NULL, spin, (void *)c);
    for (long c = 0; c < ncpu && c < MAXCPU; c++) pthread_join(th[c], NULL);
    sleep(1);
    irq_counts("arch_timer", t1);
    irq_counts("IPI", i1);
    long ipi = 0;
    for (int c = 0; c < n && c < MAXCPU; c++) {
        printf("PROOF ch36 cpu%d timer_delta=%ld\n", c, t1[c] - t0[c]);
        ipi += i1[c] - i0[c];
    }
    printf("PROOF ch36 ipi_delta=%ld\n", ipi);
    printf("PROOF done\n");
    for (;;) pause();
}
