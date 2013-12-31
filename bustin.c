
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <string.h>
#include <alloca.h>
#include <sys/mman.h>


static uint64_t PTROOT;

static uint64_t INIT_TASK = 0;
static uint64_t COMM_OFFSET = 0;
static uint64_t PID_OFFSET = 0;

typedef struct procinfo {
	int pi_pid;
	char *pi_comm;

	uint64_t pi_addr_comm;
	uint64_t pi_addr_pid;
	struct procinfo *pi_next;
} procinfo_t;

struct procinfo *PROCINFO = NULL;

typedef struct tlb {
	uint64_t tlb_vaddr;
	uint64_t tlb_paddr;
	uint64_t tlb_pagesize;
	struct tlb *tlb_next;
} tlb_t;

struct tlb *TLB = NULL;

static void
procinfo_add(procinfo_t *pi)
{
	pi->pi_next = PROCINFO;
	PROCINFO = pi;
}

static tlb_t *
tlb_find(uint64_t vaddr)
{
	tlb_t *tlb = TLB;

	for (tlb = TLB; tlb != NULL; tlb = tlb->tlb_next) {
		uint64_t end = tlb->tlb_vaddr + tlb->tlb_pagesize;
		if (vaddr >= tlb->tlb_vaddr && vaddr < end) {
			return (tlb);
		}
	}

	return (NULL);
}

static void
tlb_add(uint64_t vaddr, uint64_t paddr, uint64_t pagesize)
{
	tlb_t *tlb;

	if ((tlb = tlb_find(vaddr)) != NULL)
		return;

	if ((tlb = calloc(1, sizeof (*tlb))) == NULL) {
		fprintf(stderr, "ERROR: tlb_add calloc fail\n");
		return;
	}

	tlb->tlb_vaddr = vaddr;
	tlb->tlb_paddr = paddr;
	tlb->tlb_pagesize = pagesize;

	tlb->tlb_next = TLB;
	TLB = tlb;
}


#define	BASEA	0xfab000


#define	PT_PRESENT	(1ULL << 0)
#define	PT_WRITE	(1ULL << 1)
#define	PT_USER		(1ULL << 2)
#define	PT_PAGESIZE	(1ULL << 7)

#define	MASK_FROM_TO(upper_bit, lower_bit) \
	((((1ULL << (upper_bit - lower_bit + 1)) - 1) << lower_bit))

#define	ADDRMASK	MASK_FROM_TO(51, 12)
#define	ADDRMASK_L2	MASK_FROM_TO(51, 21)
#define	ADDRMASK_L3	MASK_FROM_TO(51, 30)

//#define	ADDRMASK	(((1ULL << (51 - 12)) - 1) << 12)
//#define	ADDRMASK_L2	(((1ULL << (51 - 20)) - 1) << 20)
//#define	ADDRMASK_L3	(((1ULL << (51 - 29)) - 1) << 29)

#define	PML4E_AMASK	(0x7fffffffffff)

#define ADDREXTEND	MASK_FROM_TO(63, 48)

static int
pload(int fd, uint64_t paddr, uint64_t size, void *buf)
{
	size_t sz;

	if ((sz = pread(fd, buf, size, BASEA + paddr)) != size) {
		fprintf(stderr, "ERROR: pread fail\n");
		return (-1);
	}

	return (0);
}

static int
vload(int fd, uint64_t ptroot, uint64_t vaddr, uint64_t size, void *buf)
{
	tlb_t *tlb = tlb_find(vaddr);

	if (tlb == NULL) {
		/*
		 * Walk page table to find mapping.
		 * XXX
		 *
		 * tlb_add(...);
		 */
		fprintf(stderr, "COULD NOT FIND MAPPING FOR %016llx\n",
		    vaddr);
		return (-1);
	}

	if ((vaddr + size) > (tlb->tlb_vaddr + tlb->tlb_pagesize)) {
		fprintf(stderr, "ERROR: CANNOT READ %016llx + %llx FROM "
		    "PAGE AT %016llx + %llx\n", vaddr, size, tlb->tlb_vaddr,
		    tlb->tlb_pagesize);
		return (-1);
	}

	return (pload(fd, tlb->tlb_paddr + (vaddr - tlb->tlb_vaddr), size,
	    buf));
}

static void
vinspect(int fd, uint64_t ptroot, uint64_t vaddr, uint64_t size)
{
	/*
	 * Make it 8-byte aligned:
	 */
	uint64_t masked = vaddr & ~0x7ULL;
	uint64_t realsize = (vaddr + size) - masked;

	char *buf = alloca(realsize);
	int i;

	fprintf(stdout, "PHASE2: DUMP %16llx (%llx)\n", vaddr, size);

	if (vload(fd, ptroot, masked, realsize, buf) == -1) {
		fprintf(stderr, "PHASE2: FAIL\n");
		return;
	}

	for (i = 0; i <= realsize + 8; i += 8) {
		int j;

		fprintf(stdout, "PHASE2: %016llx: ", masked + i);

		for (j = i; j < i + 8 && j < realsize; j++) {
			fprintf(stdout, " %02x ", 0xff & buf[j]);
		}

		fprintf(stdout, "  ");

		for (j = i; j < i + 8 && j < realsize; j++) {
			char cc = '.';

			if (buf[j] >= 'a' && buf[j] <= 'z')
				cc = buf[j];
			else if (buf[j] >= 'A' && buf[j] <= 'Z')
				cc = buf[j];
			else if (buf[j] >= '0' && buf[j] <= '9')
				cc = buf[j];

			fprintf(stdout, "%c", cc);
		}

		fprintf(stdout, "\n");
	}
}

typedef void (*walk_func_t)(int fd, uint64_t ptroot, uint64_t vaddr,
    void *arg);

void
walk_listhead(int fd, uint64_t ptroot, uint64_t vaddr, uint64_t offset,
    walk_func_t walk_func, void *arg)
{
	uint64_t next = vaddr;

	for (;;) {
		/*
		 * Load next pointer from list_head:
		 */
		if (vload(fd, ptroot, next + 8, sizeof (next),
		    (uint8_t *)&next) == -1) {
			fprintf(stdout, "PHASE2: ERROR walk\n");
			return;
		}

		/*
		 * If we've walked back to the list_head, then
		 * we're done:
		 */
		if (next == vaddr) {
			/*fprintf(stdout, "PHASE2: end walk\n");*/
			return;
		}

		/*
		 * Visit the list_entry that this list_head
		 * is embedded in:
		 */
		walk_func(fd, ptroot, next - offset, arg);
	}
}

typedef struct visit_child_state {
	int vcs_depth;
} visit_child_state_t;

static void
visit_child(int fd, uint64_t ptroot, uint64_t vaddr, void *arg)
{
	visit_child_state_t *vcs = arg;
	visit_child_state_t vcs1;
	uint32_t pid;
	char comm[16];
	int ii;

	vload(fd, ptroot, vaddr + COMM_OFFSET, sizeof (comm), comm);
	vload(fd, ptroot, vaddr + PID_OFFSET, sizeof (pid), &pid);

	for (ii = 0; ii < vcs->vcs_depth; ii++) {
		fprintf(stdout, "    ");
	}
	fprintf(stdout, "walk[%016llx]: %-6u %s\n", vaddr, pid, comm);

	/*
	 * Walk Children:
	 */
	vcs1.vcs_depth = vcs->vcs_depth + 1;
	walk_listhead(fd, ptroot, vaddr + PID_OFFSET + 28,
	    PID_OFFSET + 44, visit_child, &vcs1);
}

void
phase2(int fd, uint64_t ptroot)
{
	procinfo_t *pi;
	uint64_t pid_to_comm = 0;
	visit_child_state_t vcs0;

	for (pi = PROCINFO; pi != NULL; pi = pi->pi_next) {
		fprintf(stdout, "PHASE2: comm      %s\n", pi->pi_comm);
		fprintf(stdout, "PHASE2: pid       %d\n", pi->pi_pid);
		fprintf(stdout, "PHASE2: addr comm %016llx\n",
		    pi->pi_addr_comm);
		fprintf(stdout, "PHASE2: addr pid  %016llx\n",
		    pi->pi_addr_pid);

		if (pid_to_comm == 0) {
			pid_to_comm = pi->pi_addr_comm - pi->pi_addr_pid;
		} else {
			if (pid_to_comm != pi->pi_addr_comm -
			    pi->pi_addr_pid) {
				fprintf(stderr, "PHASE2: "
				    "mismatched pid-to-comm offset\n");
			}
		}

		vinspect(fd, ptroot, pi->pi_addr_pid, pi->pi_addr_comm -
		    pi->pi_addr_pid + 16);
		fprintf(stdout, "PHASE2: \n");
		{
			uint64_t init_task, aa, bb;
			fprintf(stdout, "PHASE2: ptr from %016llx\n",
			    pi->pi_addr_pid + 12);
			vload(fd, ptroot, pi->pi_addr_pid + 12,
			    sizeof (init_task), (uint8_t *)&init_task);
			if (INIT_TASK == 0) {
				INIT_TASK = init_task;
			} else {
				if (INIT_TASK != init_task) {
					fprintf(stderr, "PHASE2: "
					    "mismatched init task "
					    "got %016llx "
					    "expected %016llx\n",
					    init_task, INIT_TASK);
				}
			}
		}
		fprintf(stdout, "PHASE2: \n");
	}

	if (INIT_TASK == 0)
		return;

	fprintf(stdout, "PHASE2: measuring offset of COMM in init_task "
	    "@ %016llx\n", INIT_TASK);
	{
		char buf[2048];
		uint64_t i;

		if (vload(fd, ptroot, INIT_TASK, sizeof (buf), buf) == -1)
			return;

		for (i = 0; i < sizeof (buf); i++) {
			if (strncmp("swapper", &buf[i], 7) == 0) {
				COMM_OFFSET = i;
				fprintf(stdout, "PHASE2: offset of COMM == "
				    " %lld / %llx\n", i, i);
				break;
			}
		}
	}

	PID_OFFSET = COMM_OFFSET - pid_to_comm;
	fprintf(stdout, "PHASE2: list offset %llx\n", PID_OFFSET + 12 + 16);

	vcs0.vcs_depth = 0;
	fprintf(stdout, "\n\nWALK CHILDREN STARTING AT INIT_TASK:\n\n");
	walk_listhead(fd, ptroot, INIT_TASK + PID_OFFSET + 28,
	    PID_OFFSET + 44, visit_child, &vcs0);
}

static int
find_process(int fd, uint64_t ptroot, char *comm, int expid, uint64_t vaddr,
    uint64_t pagesize)
{
	char comm2[16];
	char *buf = alloca(pagesize);
	char *buf_prev = alloca(pagesize);
	uint64_t a;
	size_t sz;
	int ret = -1;
	uint32_t expid32 = expid;

	/*
	 * Set up 16-byte NUL-terminated array for comparison with
	 * the "comm" field of struct task
	 */
	bzero(comm2, sizeof (comm2));
	strcpy(comm2, comm);

	if (vload(fd, ptroot, vaddr, pagesize, buf) == -1) {
		return (-1);
	}

	for (a = 16; a < pagesize; a += 8) {
		uint64_t *load8_a, *load8_b;
		uint32_t *load4_a;

		if (bcmp(buf + a, comm2, 16) != 0)
			continue;

		printf("FOUND comm \"%s\" @ %016llx\n", comm, vaddr + a);
		if (strcmp(comm, "kthreadd") == 0) {
			vinspect(fd, ptroot, vaddr, pagesize);
		}

#if 0
		load8_a = (uint64_t *)&buf[a - 8];
		load8_b = (uint64_t *)&buf[a - 16];
		if (*load8_a != *load8_b)
			continue;
		if (*load8_a < 0xffff880000000000)
			continue;

		printf("FOUND cred == real_cred @ %016llx\n", vaddr + a);
#endif

		for (load4_a = (uint32_t *)&buf[a - 16]; load4_a > 0;
		    load4_a--) {
			if (expid32 == *load4_a) {
				uint64_t offs = (void*)load4_a - (void*)buf;
				printf("FOUND expected tgid @ %016llx (%x)\n",
				    vaddr + offs, a - offs);

				load4_a--;
				if (expid32 == *load4_a) {
					procinfo_t *pi;
					offs = (void*)load4_a - (void*)buf;
					printf("FOUND expected pid @ "
					    "%016llx (%x)\n",
					    vaddr + offs, a - offs);

					pi = calloc(1, sizeof (*pi));
					pi->pi_comm = strdup(comm);
					pi->pi_pid = *load4_a;
					pi->pi_addr_comm = vaddr + a;
					pi->pi_addr_pid = vaddr + offs;
					procinfo_add(pi);
				}

				break;
			}
		}

		ret = 0;
		goto out;
	}

out:
	free(buf);
	return (ret);
}


static int
grep_mem(int fd, char *grepstr, uint64_t vaddr, uint64_t physaddr,
    uint64_t pagesize)
{
	char *buf = NULL;
	uint64_t a;
	int greplen = strlen(grepstr);
	size_t sz;
	int ret = -1;

	buf = malloc(pagesize);
	if (buf == NULL) {
		perror("malloc");
		goto out;
	}

	if ((sz = pread(fd, buf, pagesize, BASEA + physaddr)) != pagesize) {
		fprintf(stderr, "sz: %d\n", sz);
		perror("pread");
		goto out;
	}

	for (a = 0; a < pagesize; a++) {
		if (strncmp(buf + a, grepstr, greplen) == 0) {
			printf("FOUND %s @ %016llx (phys %016llx)\n",
			    grepstr, vaddr + a, physaddr + a);
			ret = 0;
		}
	}

out:
	free(buf);
	return (ret);
}

void
inspect_kernel(int fd, uint64_t vaddr, uint64_t physaddr, uint64_t pagesize)
{
	char *buf = malloc(pagesize);
	int i;

	if (pread(fd, buf, pagesize, BASEA + physaddr) != pagesize) {
		perror("pread");
		free(buf);
		return;
	}

	fprintf(stderr, "DUMP %16llx --> %16llx (%llx)\n", vaddr,
		vaddr + pagesize - 1, pagesize);

	for (i = 0; i <= pagesize + 8; i += 8) {
		int j;

		printf("I %016llx: ", vaddr + i);

		for (j = i; j < i + 8 && j < pagesize; j++) {
			printf(" %02x ", 0xff & buf[j]);
		}

		printf("  ");

		for (j = i; j < i + 8 && j < pagesize; j++) {
			char cc = '.';

			if (buf[j] >= 'a' && buf[j] <= 'z')
				cc = buf[j];
			else if (buf[j] >= 'A' && buf[j] <= 'Z')
				cc = buf[j];
			else if (buf[j] >= '0' && buf[j] <= '9')
				cc = buf[j];

			printf("%c", cc);
		}

		printf("\n");
	}
	printf("\n");

	if (getenv("DO_MDB") != NULL) {
		printf("\n");
		for (i = 0; i < pagesize; i++) {
			uint8_t c = buf[i];
			printf("%x/v 0t%u\n", i, (unsigned int) c);
		}
		printf("\n");
	}

	free(buf);
}

uint64_t IDENTITY_MIN = 0xffffc7ffffffffff;
uint64_t IDENTITY_MAX = 0xffff880000000000;

void
look_here(int fd, uint64_t vaddr, uint64_t physaddr, uint64_t pagesize)
{
	/*
	 * Care only for Kernel memory right now.
	 */
	if (vaddr < 0xffff800000000000)
		return;

	/*
	 * Record the bounds of the identity map:
	 */
	if (vaddr >= 0xffff880000000000 && vaddr <= 0xffffc7ffffffffff) {
		if (vaddr < IDENTITY_MIN)
			IDENTITY_MIN = vaddr;
		if (vaddr > IDENTITY_MAX)
			IDENTITY_MAX = vaddr;
	}

	/*
	 * Ignore vsyscalls, etc:
	 */
	if (vaddr >= 0xffffffffff5fa000)
		return;
}

static int
phase1(int fd, uint64_t ptroot)
{
	uint8_t buf[4096];
	uint64_t pos;
	int found1 = 0, found2 = 0;

	fprintf(stdout, "PHASE1: from %016llx downto %016llx\n",
	    IDENTITY_MAX & ~(0xfffULL), IDENTITY_MIN);

	for (pos = IDENTITY_MAX & ~(0xfffULL); pos >= IDENTITY_MIN;
	    pos -= 4096) {
		if (vload(fd, ptroot, pos, sizeof (buf), buf) == -1)
			continue;

		if (!found2 && find_process(fd, ptroot, "kthreadd", 2, pos,
		    4096) == 0) {
			found2 = 1;
		}
		if (!found1 && find_process(fd, ptroot, "init", 1, pos,
		    4096) == 0) {
			found1 = 1;
		}

		if (found1 && found2) {
			fprintf(stdout, "FOUND BOTH init AND kthreadd\n");
			return (0);
		}
	}
	return (-1);
}


/*
 * PML4
 *   0: PRESENT (1 to reference a PML3/PDP table)
 *   1: WRITE (0 for READ)
 *   2: USER (0 for SUPERVISOR ONLY)
 *   51:12 --> PML3 ADDRESS
 *
 * PML3 (PDP)
 *   0: PRESENT
 *   1: WRITE
 *   2: USER
 *   7: PAGESIZE (PS) -- 1 for 1GB page; 0 for PML2 reference
 *   51:30 --> 1GB PAGE PHYS ADDR  (PS=1)
 *     or
 *   51:12 --> PML2 ADDRESS (PS=0)
 *
 * PML2 (PD)
 *   0: PRESENT
 *   1: WRITE
 *   2: USER
 *   7: PAGESIZE (PS) -- 1 for 2MB page; 0 for PML1 reference
 *   51:21 --> 2MB PAGE PHYS ADDR (PS=1)
 *     or
 *   51:12 --> PML1 ADDRESS (PS=0)
 *
 * PML1
 *   0: PRESENT
 *   1: WRITE
 *   2: USER
 *   51:12 --> 4KB PAGE PHYS ADDR
 */

static char *indents[] = {
	"",
	"       ",	/* L1 */
	"     ",	/* L2 */
	"   ",		/* L3 */
	" ",		/* L4 */
};

void
print_pte(int level, int index, uint64_t vaddr, uint64_t pagesize,
    uint64_t physaddr)
{
	char *label = pagesize == 2097152 ? "2M" :
	    pagesize == 1073741824 ? "1G" :
	    pagesize == 4096 ? "4K" :
	    "PT";
	static int print_pte = -1;

	if (print_pte == -1)
		print_pte = getenv("PRINT_PTE") != NULL ? 1 : 0;
	if (!print_pte)
		return;

	if (strcmp(label, "PT") == 0) {
		fprintf(stdout, "%d%s[%d] %016llx (%s)\n",
		    level, indents[level], index,
		    vaddr, label);
	} else {
		fprintf(stdout, "%d%s[%d] %016llx - %016llx (%s) :: %llx\n",
		    level, indents[level], index,
		    vaddr, vaddr + pagesize - 1, label,
		    physaddr);
	}
}

void
walk_map(int fd, int level, uint64_t ptaddr, uint64_t base_vaddr)
{
	uint64_t i;
	uint64_t pt[512];

	if (level < 1 || level > 4)
		abort();

	/*
	 * Read the page table page from the guest address space:
	 */
	if (pread(fd, pt, sizeof (pt), BASEA + ptaddr) != sizeof (pt)) {
		perror("walk_map pread");
		return;
	}

	if (level == 4)
		base_vaddr = 0;

	for (i = 0; i < (sizeof (pt) / sizeof (*pt)); i++) {
		uint64_t pte = pt[i];
		uint64_t nextaddr;
		uint64_t vaddr = base_vaddr;

		if (!(pte & PT_PRESENT)) {
			continue;
		}

		vaddr |= i << (
			level == 4 ? 39 :
			level == 3 ? 30 :
			level == 2 ? 21 :
			level == 1 ? 12 : 0);
		if (vaddr & (1ULL << 47))
			vaddr |= ADDREXTEND;

		if ((level == 2 || level == 3) && (pte & PT_PAGESIZE)) {
			/*
			 * This is a large page:
			 */
			//char *label = level == 2 ? "2M" : "1G";
			uint64_t pagesize = level == 2 ? 2097152 :
			    1073741824;
			uint64_t physaddr = pte & (level == 2 ? ADDRMASK_L2 :
			    ADDRMASK_L3);

			print_pte(level, i, vaddr, pagesize, physaddr);

			tlb_add(vaddr, physaddr, pagesize);
			look_here(fd, vaddr, physaddr, pagesize);

			continue;
		}

		nextaddr = (pte & ADDRMASK);
		if (level > 1) {
			print_pte(level, i, vaddr, 0, nextaddr);
			walk_map(fd, level - 1, nextaddr, vaddr);
		} else {
			print_pte(level, i, vaddr, 4096, nextaddr);
			tlb_add(vaddr, nextaddr, 4096);
			look_here(fd, vaddr, nextaddr, 4096);
		}
	}
}

int
main(int argc, char **argv)
{
	int fd;
	char *path;
	uint64_t ptroot;

	if (argc < 3) {
		fprintf(stderr, "args: <pid> <ptrootaddr>\n");
		exit(1);
	}

	if (asprintf(&path, "/proc/%d/as", atoi(argv[1])) < 0) {
		err(1, "asprintf");
	}

	errno = 0;
	ptroot = strtoull(argv[2], NULL, 16);
	if (errno != 0) {
		err(1, "strtoll");
	}

	fprintf(stderr, "opening: %s\n", path);
	fprintf(stderr, "ptaddr: %llx\n", ptroot);

	if ((fd = open(path, O_RDONLY)) == -1) {
		err(1, "could not open as");
	}

	walk_map(fd, 4, ptroot, 0);
	/*do_things(fd, ptroot);*/

	if (phase1(fd, ptroot) != 0) {
		fprintf(stdout, "PHASE 1 FAILED\n");
	}

	phase2(fd, ptroot);

	(void) close(fd);

	return (0);
}
