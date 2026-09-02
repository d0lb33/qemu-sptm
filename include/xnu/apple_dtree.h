#pragma once

#include <stdint.h>
#include <stddef.h>

#define kDTPathNameSeparator "/"
#define kDTMaxPropertyNameLength 31
#define kDTMaxEntryNameLength 63
#define kPropNameLength 32

struct dtree_prop {
    char      name[kPropNameLength];
    uint32_t  length;
};

struct dtree_node {
    uint32_t nProperties;
    uint32_t nChildren;
    // dtree_prop[nProperties]
    // dtree_node[nChildren]
};

struct adt_io_reg {
    uint64_t base;
    uint64_t len;
};

// Child iteration. Walk a node's children with:
//   for (struct dtree_node *c = adt_first_child(n); c; c = adt_next_sibling(n, c))
struct dtree_node *adt_first_child(struct dtree_node *n);
struct dtree_node *adt_next_sibling(struct dtree_node *parent, struct dtree_node *child);

struct dtree_node *adt_find_node(struct dtree_node *root, const char *path);
void *adt_get_prop_val(struct dtree_node *n, const char *prop_name);
size_t adt_get_prop_len(struct dtree_node *n, const char *prop_name);
