#ifndef XNU_DARWIN_AES_H
#define XNU_DARWIN_AES_H
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"
void darwin_aes_create(struct dtree_node *root, uint64_t iobase, DeviceState *aic);
#endif
