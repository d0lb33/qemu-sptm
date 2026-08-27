#pragma once

// xnu-12377.121.6/bsd/sys/trust_caches.h:65
// (jprx note: I changed offsets[0] -> [1] to make sizeof correct)

/* This is the structure iBoot uses to deliver the trust caches to the system */
typedef struct _trust_cache_offsets {
	/* The number of trust caches provided */
	uint32_t num_caches;

	/* Offset of each from beginning of the structure */
	uint32_t offsets[1];
} __attribute__((__packed__)) trust_cache_offsets_t;
