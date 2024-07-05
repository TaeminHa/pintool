/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include "pin.H"
//Imported from libnuma to not have to link to libnuma inside pintool

#ifndef NUMAIF_H
#define NUMAIF_H 1

#include <cstdlib>

// If keep move_pages it generates symbol error on last pin version (3.24), so use another symbol name to avoid issues.
#define move_pages move_pages_pintool
#endif //NUMAIF_H

#include <unistd.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <errno.h>
#include <cstdio>
#include <sys/syscall.h> 
#include <unordered_map>
#include <mutex>
//#include "numa.h"
//#include "numaif.h"
//#include "numaint.h"

#define WEAK __attribute__((weak))

#if !defined(__NR_move_pages)

#if defined(__x86_64__)

#define __NR_sched_setaffinity    203
#define __NR_sched_getaffinity     204

/* Official allocation */

#define __NR_mbind 237
#define __NR_set_mempolicy 238
#define __NR_get_mempolicy 239
#define __NR_migrate_pages 256
#define __NR_move_pages 279

#elif defined(__ia64__)
#define __NR_sched_setaffinity    1231
#define __NR_sched_getaffinity    1232
#define __NR_migrate_pages	1280
#define __NR_move_pages 1276

/* Official allocation */

#define __NR_mbind 1259
#define __NR_get_mempolicy 1260
#define __NR_set_mempolicy 1261

#elif defined(__i386__)

#define __NR_mbind 274
#define __NR_get_mempolicy 275
#define __NR_set_mempolicy 276
#define __NR_migrate_pages 294
#define __NR_move_pages 317

#elif defined(__powerpc__)

#define __NR_mbind 259
#define __NR_get_mempolicy 260
#define __NR_set_mempolicy 261
#define __NR_migrate_pages 258
/* FIXME: powerpc is missing move pages!!!
#define __NR_move_pages xxx
*/

#elif defined(__mips__)

#if _MIPS_SIM == _ABIO32
/*
 * Linux o32 style syscalls are in the range from 4000 to 4999.
 */
#define __NR_Linux 4000
#define __NR_mbind (__NR_Linux + 268)
#define __NR_get_mempolicy (__NR_Linux + 269)
#define __NR_set_mempolicy (__NR_Linux + 270)
#define __NR_migrate_pages (__NR_Linux + 287)
#endif

#if _MIPS_SIM == _ABI64
/*
 * Linux 64-bit syscalls are in the range from 5000 to 5999.
 */
#define __NR_Linux 5000
#define __NR_mbind (__NR_Linux + 227)
#define __NR_get_mempolicy (__NR_Linux + 228)
#define __NR_set_mempolicy (__NR_Linux + 229)
#define __NR_migrate_pages (__NR_Linux + 246)
#endif

#if _MIPS_SIM == _ABIN32
/*
 * Linux N32 syscalls are in the range from 6000 to 6999.
 */
#define __NR_Linux 6000
#define __NR_mbind (__NR_Linux + 231)
#define __NR_get_mempolicy (__NR_Linux + 232)
#define __NR_set_mempolicy (__NR_Linux + 233)
#define __NR_migrate_pages (__NR_Linux + 250)
#endif

#elif defined(__hppa__)

#define __NR_migrate_pages	272

#elif !defined(DEPS_RUN)
#error "Add syscalls for your architecture or update kernel headers"
#endif

#endif

#ifndef __GLIBC_PREREQ
# define __GLIBC_PREREQ(x,y) 0
#endif

//#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 11)
#if 1

/* glibc 2.11 seems to have working 6 argument sycall. Use the
   glibc supplied syscall in this case.
   The version cut-off is rather arbitary and could be probably
   earlier. */
#define syscall6 syscall
#elif defined(__x86_64__)
/* 6 argument calls on x86-64 are often buggy in both glibc and
   asm/unistd.h. Add a working version here. */
long syscall6(long call, long a, long b, long c, long d, long e, long f)
{
	   long res;
	   asm volatile ("movq %[d],%%r10 ; movq %[e],%%r8 ; movq %[f],%%r9 ; syscall"
			 : "=a" (res)
			 : "0" (call),"D" (a),"S" (b), "d" (c),
			   [d] "g" (d), [e] "g" (e), [f] "g" (f) :
			 "r11","rcx","r8","r10","r9","memory" );
	   if (res < 0) {
		   errno = -res;
		   res = -1;
	   }
	   return res;
}
#elif defined(__i386__)

/* i386 has buggy syscall6 in glibc too. This is tricky to do
   in inline assembly because it clobbers so many registers. Do it
   out of line. */
asm(
"__syscall6:\n"
"	pushl %ebp\n"
"	pushl %edi\n"
"	pushl %esi\n"
"	pushl %ebx\n"
"	movl  (0+5)*4(%esp),%eax\n"
"	movl  (1+5)*4(%esp),%ebx\n"
"	movl  (2+5)*4(%esp),%ecx\n"
"	movl  (3+5)*4(%esp),%edx\n"
"	movl  (4+5)*4(%esp),%esi\n"
"	movl  (5+5)*4(%esp),%edi\n"
"	movl  (6+5)*4(%esp),%ebp\n"
"	int $0x80\n"
"	popl %ebx\n"
"	popl %esi\n"
"	popl %edi\n"
"	popl %ebp\n"
"	ret"
);
extern long __syscall6(long n, long a, long b, long c, long d, long e, long f);

long syscall6(long call, long a, long b, long c, long d, long e, long f)
{
	   long res = __syscall6(call,a,b,c,d,e,f);
	   if (res < 0) {
		   errno = -res;
		   res = -1;
	   }
	   return res;
}

#else
#define syscall6 syscall
#endif

/*******************  FUNCTION  *********************/
long move_pages(int pid, unsigned long count,void **pages, const int *nodes, int *status, int flags)
{
	return syscall6(__NR_move_pages, (long)pid, (long)count,(long) pages,(long) nodes, (long)status, flags);
}

/*******************  FUNCTION  *********************/
long set_mempolicy(int mode, const unsigned long *nmask,unsigned long maxnode)
{
	long i;
	i = syscall(__NR_set_mempolicy,mode,nmask,maxnode);
	return i;
}

/*******************  FUNCTION  *********************/
long get_mempolicy(int *policy, unsigned long *nmask,unsigned long maxnode, void *addr,unsigned flags)
{
	return syscall(__NR_get_mempolicy, policy, nmask,
					maxnode, addr, flags);
}

#define BUFFER_SIZE 1024 * 1024 * 256 

class Thread
{
public:
    int tid;
    int node_id;
    std::string buffer;
    FILE* trace;

    Thread(int t) : tid(t) {
        buffer.reserve(BUFFER_SIZE);
        trace = fopen(("/mydata/results/pinatrace/" + std::to_string(tid) + ".out").c_str(), "w");
        if (trace == nullptr) {
            // Handle file open error
            perror("Failed to open file");
        }
    }

    ~Thread() {
        if (trace != nullptr) {
            fwrite(buffer.c_str(), sizeof(char), buffer.size(), trace);
            fflush(trace);        
            fclose(trace);
        }
    }
};

std::unordered_map<THREADID, Thread*> thread_map;
std::mutex thread_map_mutex;

// Print a memory read record
VOID RecordMemRead(VOID* ip, VOID* addr) {
    int status[1];
    status[0] = -1;

    unsigned int cpu_id;
    unsigned int node_id;

    move_pages(0, 1, &addr, NULL, status, 0); 
	
    syscall(SYS_getcpu, &cpu_id, &node_id);

    THREADID tid = PIN_ThreadId();
    std::lock_guard<std::mutex> lock(thread_map_mutex);
    Thread* thread = thread_map[tid];
    if (thread) {
        if (static_cast<unsigned int>(status[0]) == node_id)
            thread->buffer += "RL (" + std::to_string(node_id) + " " + std::to_string(status[0]) + ") " + std::to_string(reinterpret_cast<uintptr_t>(addr)) + ",";
        else
            thread->buffer += "RR (" + std::to_string(node_id) + " " + std::to_string(status[0]) + ") " + std::to_string(reinterpret_cast<uintptr_t>(addr)) + ",";
        if (thread->buffer.size() > BUFFER_SIZE) {
            fwrite(thread->buffer.c_str(), sizeof(char), thread->buffer.size(), thread->trace);
            thread->buffer.clear();
        }
    }
}

// Print a memory write record
VOID RecordMemWrite(VOID* ip, VOID* addr) { 
    int status[1];
    status[0] = -1;

    unsigned int cpu_id;
    unsigned int node_id;

    move_pages(0, 1, &addr, NULL, status, 0); 
	
    syscall(SYS_getcpu, &cpu_id, &node_id);

    THREADID tid = PIN_ThreadId();
    std::lock_guard<std::mutex> lock(thread_map_mutex);
    Thread* thread = thread_map[tid];
    if (thread) {
        if (static_cast<unsigned int>(status[0]) == node_id)
            thread->buffer += "WL (" + std::to_string(node_id) + " " + std::to_string(status[0]) + ") " + std::to_string(reinterpret_cast<uintptr_t>(addr)) + ",";
        else
            thread->buffer += "WR (" + std::to_string(node_id) + " " + std::to_string(status[0]) + ") " + std::to_string(reinterpret_cast<uintptr_t>(addr)) + ",";
        
        if (thread->buffer.size() > BUFFER_SIZE) {
            fwrite(thread->buffer.c_str(), sizeof(char), thread->buffer.size(), thread->trace);
            thread->buffer.clear();
        }
    }
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID* v)
{
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
    }
}

VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    std::lock_guard<std::mutex> lock(thread_map_mutex);
    thread_map[threadid] = new Thread(threadid);
}
 
// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    std::lock_guard<std::mutex> lock(thread_map_mutex);
    Thread* thread = thread_map[threadid];
    fwrite(thread->buffer.c_str(), sizeof(char), thread->buffer.size(), thread->trace);
    delete thread;
    thread_map.erase(threadid);
}

VOID Fini(INT32 code, VOID* v)
{
    for (auto& entry : thread_map) {
        fwrite(entry.second->buffer.c_str(), sizeof(char), entry.second->buffer.size(), entry.second->trace);
        delete entry.second;
    }
    thread_map.clear();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    INS_AddInstrumentFunction(Instruction, 0);
    
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}