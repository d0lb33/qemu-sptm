#ifndef DARWIN_GPU_TRANSPORT_H
#define DARWIN_GPU_TRANSPORT_H

/* Experimental ABI shared with the standalone guest probe. */
#define DVM_GPU_RAM_BASE 0x4f0000000ULL
#define DVM_GPU_RAM_SIZE 0x1000000ULL
#define DVM_GPU_REG_BASE (DVM_GPU_RAM_BASE + DVM_GPU_RAM_SIZE)
#define DVM_GPU_REG_SIZE 0x4000ULL
#define DVM_GPU_MAGIC 0x44564d31U
#define DVM_GPU_OPEN_TYPE 0x44564d54U
#define DVM_GPU_MEMORY_TYPE 0x44560000U
#define DVM_GPU_REQUEST_HEADER 0x40U
#define DVM_GPU_REPLY_HEADER 0x80U
#define DVM_GPU_REQUEST_DATA 0x10000U
#define DVM_GPU_REPLY_DATA 0x800000U
#define DVM_GPU_LIBRARY_DATA 0xc00000U
#define DVM_GPU_MAX_BYTES 0x400000U
#define DVM_GPU_REG_DOORBELL 0x20U
#define DVM_GPU_REG_DONE 0x28U
#define DVM_GPU_REG_ERROR 0x30U
#define DVM_GPU_REG_MODE 0x38U
#define DVM_GPU_REG_SUBMITTED 0x40U
#define DVM_GPU_REG_READY 0x48U

struct dtree_node;
void darwin_gpu_transport_init(struct dtree_node *root, unsigned long long iobase);
#endif
