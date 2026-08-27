#pragma once
#include "xnu/mach-o/loader.h"
#include "xnu/mach-o/macho_arm64.h"
#include "xnu/boot/args.h"
#include "xnu/boot/xnuboot.h"

typedef struct {
    u8     *macho;
    hwaddr  physlo;
    hwaddr  virtlo, virthi;
    hwaddr  entrypoint;
} macho_info_t;

typedef struct mach_header_64 mh_t;
typedef struct load_command lc_t;
typedef struct segment_command_64 seg_t;
typedef struct section_64 sect_t;
typedef struct fileset_entry_command fse_t;

bool           is_im4p(u8 *macho);
macho_info_t   macho_get_info(u8 *macho);
void           macho_verify_header(u8 *macho, bool is_kc);
void           macho_load(macho_info_t *mi, hwaddr phys_base);
void           macho_load_seg_at(macho_info_t *mi, seg_t *lc, hwaddr paddr);
fse_t         *macho_find_fileset_entry(u8 *macho, const char *name);
seg_t         *macho_find_seg(u8 *macho, const char *name);
sect_t        *macho_find_sect(u8 *macho, const char *segname, const char *sectname);
