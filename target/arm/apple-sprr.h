/*
 * Apple SPRR leaf permission decoding, independent of host accelerator APIs.
 *
 * Permission table and index: https://asahilinux.org/docs/hw/cpu/sprr-gxf/
 * Also agrees with the existing get_S1prot_sprr() in target/arm/ptw.c.
 * Configuration locks, register banking and GXF transitions are separate.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARM_APPLE_SPRR_H
#define TARGET_ARM_APPLE_SPRR_H

#include <stdbool.h>
#include <stdint.h>

enum {
    ARM_SPRR_READ = 1,
    ARM_SPRR_WRITE = 2,
    ARM_SPRR_EXEC = 4,
};

static inline unsigned arm_sprr_leaf_index(uint64_t descriptor)
{
    /* AP[1:0], UXN, PXN form an index, not ordinary ARM access bits. */
    return ((descriptor >> 6) & 3) << 2 | ((descriptor >> 53) & 3);
}

static inline unsigned arm_sprr_leaf_permissions(uint64_t permission_register,
                                                 uint64_t descriptor,
                                                 bool guarded)
{
    static const uint8_t el_permissions[16] = {
        0, 5, 1, 3, 0, 5, 1, 0, 0, 4, 1, 3, 0, 5, 1, 3,
    };
    static const uint8_t gl_permissions[16] = {
        0, 0, 0, 0, 5, 5, 5, 5, 1, 1, 1, 1, 3, 3, 3, 3,
    };
    unsigned index = arm_sprr_leaf_index(descriptor);
    unsigned attribute = (permission_register >> (4 * index)) & 15;

    return guarded ? gl_permissions[attribute] : el_permissions[attribute];
}

#endif
