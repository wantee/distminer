#ifndef _DISTMINER_SCANHASH_SSE4_64_H_
#define _DISTMINER_SCANHASH_SSE4_64_H_

#include <stdbool.h>
#include <stdint.h>

bool scanhash_sse4_64_peon(const unsigned char *pmidstate,
	unsigned char *pdata,
	unsigned char *phash1, unsigned char *phash,
	const unsigned char *ptarget,
	uint32_t max_nonce, uint32_t *last_nonce,
	uint32_t nonce);

#endif
