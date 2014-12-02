#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

#include <netinet/tcp.h>

#include "peon_utils.h"

static inline uint32_t swab32(uint32_t v)
{
	return bswap_32(v);
}

static inline void swap256(void *dest_p, const void *src_p)
{
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;

	dest[0] = src[7];
	dest[1] = src[6];
	dest[2] = src[5];
	dest[3] = src[4];
	dest[4] = src[3];
	dest[5] = src[2];
	dest[6] = src[1];
	dest[7] = src[0];
}

bool fulltest(const unsigned char *hash, const unsigned char *target)
{
	unsigned char hash_swap[32], target_swap[32];
	uint32_t *hash32 = (uint32_t *) hash_swap;
	uint32_t *target32 = (uint32_t *) target_swap;
	bool rc = true;
	int i;

	swap256(hash_swap, hash);
	swap256(target_swap, target);

	for (i = 0; i < 32/4; i++) {
		uint32_t h32tmp = swab32(hash32[i]);
		uint32_t t32tmp = target32[i];

		target32[i] = swab32(target32[i]);	/* for printing */

		if (h32tmp > t32tmp) {
			rc = false;
			break;
		}
		if (h32tmp < t32tmp) {
			rc = true;
			break;
		}
	}

	return rc;
}

