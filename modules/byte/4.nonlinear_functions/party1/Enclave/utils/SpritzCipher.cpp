
















#include "SpritzCipher.h" 

#define SPRITZ_N_MINUS_1 255U 
#define SPRITZ_N_HALF 128U    

static inline void
spritz_state_s_swap(spritz_ctx *ctx, uint8_t index_a, uint8_t index_b)
{
#ifdef SPRITZ_WIPE_TRACES_PARANOID
  ctx->tmp1 = ctx->s[index_a];
  ctx->s[index_a] = ctx->s[index_b];
  ctx->s[index_b] = ctx->tmp1;
#else
  uint8_t tmp = ctx->s[index_a];
  ctx->s[index_a] = ctx->s[index_b];
  ctx->s[index_b] = tmp;
#endif 
}

static inline void
spritz_state_init(spritz_ctx *ctx)
{
  uint8_t i = 0;

  
  do
  {
    ctx->s[i] = i;
  } while (++i);

  ctx->i = 0;
  ctx->j = 0;
  ctx->k = 0;
  ctx->z = 0;
  ctx->a = 0;
  ctx->w = 1U;
}

static inline void
update(spritz_ctx *ctx)
{
  ctx->i = (uint8_t)(ctx->i + ctx->w);
  ctx->j = (uint8_t)(ctx->s[(uint8_t)(ctx->s[ctx->i] + ctx->j)] + ctx->k);
  ctx->k = (uint8_t)(ctx->s[ctx->j] + ctx->k + ctx->i);
  spritz_state_s_swap(ctx, ctx->i, ctx->j);
}

static inline void
whip(spritz_ctx *ctx)
{
  uint8_t i;

  for (i = 0; i < SPRITZ_N_HALF; i++)
  {
    update(ctx);
    update(ctx);
    update(ctx);
    update(ctx);
  }

  ctx->w = (uint8_t)(ctx->w + 2U);
}

#ifdef SPRITZ_TIMING_SAFE_CRUSH
static inline void

#if defined(__GNUC__) && !defined(__clang__)
    __attribute__((optimize("O0")))

#elif defined(__clang__)
    __attribute__((optnone))
#endif
    crush(spritz_ctx *ctx)
{
  uint8_t i = 0, j = SPRITZ_N_MINUS_1;
#ifdef SPRITZ_WIPE_TRACES_PARANOID
  for (; i < SPRITZ_N_HALF; i++, j--)
  {
    ctx->tmp1 = ctx->s[i]; 
    ctx->tmp2 = ctx->s[j]; 
    if (ctx->tmp1 > ctx->tmp2)
    {                        
      ctx->s[i] = ctx->tmp2; 
      ctx->s[j] = ctx->tmp1; 
    }
    else
    {
      ctx->s[i] = ctx->tmp1; 
      ctx->s[j] = ctx->tmp2; 
    }
  }
#else  
  uint8_t s_i, s_j;
  for (; i < SPRITZ_N_HALF; i++, j--)
  {
    s_i = ctx->s[i];
    s_j = ctx->s[j];
    if (s_i > s_j)
    {
      ctx->s[i] = s_j;
      ctx->s[j] = s_i;
    }
    else
    {
      ctx->s[i] = s_i;
      ctx->s[j] = s_j;
    }
  }
#endif 
}
#else  

static void
crush(spritz_ctx *ctx)
{
  uint8_t i = 0, j = SPRITZ_N_MINUS_1;
  for (; i < SPRITZ_N_HALF; i++, j--)
  {
    if (ctx->s[i] > ctx->s[j])
    {
      spritz_state_s_swap(ctx, i, j);
    }
  }
}
#endif 

static inline void
shuffle(spritz_ctx *ctx)
{
  whip(ctx);
  crush(ctx);
  whip(ctx);
  crush(ctx);
  whip(ctx);
  ctx->a = 0;
}


static inline void
absorbNibble(spritz_ctx *ctx, const uint8_t nibble)
{
  if (ctx->a == SPRITZ_N_HALF)
  {
    shuffle(ctx);
  }
  spritz_state_s_swap(ctx, ctx->a, (uint8_t)(SPRITZ_N_HALF + nibble));
  ctx->a++;
}
static inline void
absorb(spritz_ctx *ctx, const uint8_t octet)
{
  absorbNibble(ctx, octet % 16); 
  absorbNibble(ctx, octet / 16); 
}
static inline void
absorbBytes(spritz_ctx *ctx, const uint8_t *buf, uint16_t len)
{
  uint16_t i;

  for (i = 0; i < len; i++)
  {
    absorb(ctx, buf[i]);
  }
}

static inline void
absorbStop(spritz_ctx *ctx)
{
  if (ctx->a == SPRITZ_N_HALF)
  {
    shuffle(ctx);
  }

  ctx->a++;
}

static inline uint8_t
output(spritz_ctx *ctx)
{
  ctx->z = ctx->s[(ctx->s[(ctx->s[(ctx->z + ctx->k) % SPRITZ_N] + ctx->i) % SPRITZ_N] + ctx->j) % SPRITZ_N];
  return ctx->z;
}

static inline uint8_t
drip(spritz_ctx *ctx)
{
  if (ctx->a)
  {
    shuffle(ctx);
  }
  update(ctx);
  return output(ctx);
}















uint8_t

#if defined(__GNUC__) && !defined(__clang__)
    __attribute__((optimize("O0")))

#elif defined(__clang__)
    __attribute__((optnone))
#endif
    spritz_compare(const uint8_t *data_a, const uint8_t *data_b, uint16_t len)
{
  uint8_t d = 0;
  uint16_t i;

  for (i = 0; i < len; i++)
  {
    d |= data_a[i] ^ data_b[i];
  }

#ifdef SPRITZ_WIPE_TRACES_PARANOID
#if !defined(__GNUC__) && !defined(__clang__)
  
  


  d |= d >> 1; 
  d |= d >> 2; 
  d |= d >> 3; 
  d |= d >> 4; 
  d |= d >> 5; 
  d |= d >> 6; 
  d |= d >> 7; 
  d &= 1;      
#else
  
  
  if (d == 0U)
  {
    d = 0U;
  }
  else
  {
    d = 1U;
  }
#endif 
#endif 

  return d;
}







void

#if defined(__GNUC__) && !defined(__clang__)
    __attribute__((optimize("O0")))

#elif defined(__clang__)
    __attribute__((optnone))
#endif
    spritz_memzero(uint8_t *buf, uint16_t len)
{
#ifdef SPRITZ_USE_LIBC
  memset(buf, 0, len * sizeof(uint8_t));
#else
  uint16_t i;

  for (i = 0; i < len; i++)
  {
    buf[i] = 0;
  }
#endif
}






void

#if defined(__GNUC__) && !defined(__clang__)
    __attribute__((optimize("O0")))

#elif defined(__clang__)
    __attribute__((optnone))
#endif
    spritz_state_memzero(spritz_ctx *ctx)
{
#ifdef SPRITZ_USE_LIBC
  memset(ctx->s, 0, SPRITZ_N);
#else
  uint8_t i = 0;
  
  do
  {
    ctx->s[i] = 0;
  } while (++i);
#endif

  ctx->i = 0;
  ctx->j = 0;
  ctx->k = 0;
  ctx->z = 0;
  ctx->a = 0;
  ctx->w = 0;

#ifdef SPRITZ_WIPE_TRACES_PARANOID
  ctx->tmp1 = 0;
  ctx->tmp2 = 0;
#endif
}








void spritz_setup(spritz_ctx *ctx,
                  const uint8_t *key, uint8_t keyLen)
{
  spritz_state_init(ctx);
  absorbBytes(ctx, key, keyLen);
  if (ctx->a)
  {
    shuffle(ctx);
  }
}










void spritz_setup_withIV(spritz_ctx *ctx,
                         const uint8_t *key, uint8_t keyLen,
                         const uint8_t *nonce, uint8_t nonceLen)
{
  spritz_state_init(ctx);
  absorbBytes(ctx, key, keyLen);
  absorbStop(ctx);
  absorbBytes(ctx, nonce, nonceLen);
  if (ctx->a)
  {
    shuffle(ctx);
  }
}









uint8_t
spritz_random8(spritz_ctx *ctx)
{
  return drip(ctx);
}









uint32_t
spritz_random32(spritz_ctx *ctx)
{
  return (uint32_t)(((uint32_t)(drip(ctx)) << 0) | ((uint32_t)(drip(ctx)) << 8) | ((uint32_t)(drip(ctx)) << 16) | ((uint32_t)(drip(ctx)) << 24));
}

uint64_t
spritz_random64(spritz_ctx *ctx)
{
  return (uint64_t)(((uint64_t)(drip(ctx)) << 0) | ((uint64_t)(drip(ctx)) << 8) | ((uint64_t)(drip(ctx)) << 16) | ((uint64_t)(drip(ctx)) << 24) | ((uint64_t)(drip(ctx)) << 32) | ((uint64_t)(drip(ctx)) << 40) | ((uint64_t)(drip(ctx)) << 48) | ((uint64_t)(drip(ctx)) << 56));
}

void spritz_random64_flush(spritz_ctx *ctx)
{
  drip(ctx);
  drip(ctx);
  drip(ctx);
  drip(ctx);
  drip(ctx);
  drip(ctx);
  drip(ctx);
  drip(ctx);
}

















uint32_t
spritz_random32_uniform(spritz_ctx *ctx, uint32_t upper_bound)
{
  uint32_t r, min;

  if (upper_bound < 2U)
  {
    return 0;
  }

  
  min = (uint32_t)(-upper_bound % upper_bound);

  




  for (;;)
  {
    r = spritz_random32(ctx);
    if (r >= min)
    {
      return (uint32_t)(r % upper_bound);
    }
  }
}









void spritz_add_entropy(spritz_ctx *ctx,
                        const uint8_t *entropy, uint16_t len)
{
  absorbBytes(ctx, entropy, len);
}










void spritz_crypt(spritz_ctx *ctx,
                  const uint8_t *data, uint16_t dataLen,
                  uint8_t *dataOut)
{
  uint16_t i;

  for (i = 0; i < dataLen; i++)
  {
    dataOut[i] = data[i] ^ drip(ctx);
  }
}










void spritz_crypt_inplace(spritz_ctx *ctx,
                          uint8_t *data, uint16_t dataLen)
{
  uint16_t i;

  for (i = 0; i < dataLen; i++)
  {
    data[i] ^= drip(ctx);
  }
}






void spritz_hash_setup(spritz_ctx *hash_ctx)
{
  spritz_state_init(hash_ctx);
}








void spritz_hash_update(spritz_ctx *hash_ctx,
                        const uint8_t *data, uint16_t dataLen)
{
  absorbBytes(hash_ctx, data, dataLen);
}








void spritz_hash_final(spritz_ctx *hash_ctx,
                       uint8_t *digest, uint8_t digestLen)
{
  uint8_t i;

  absorbStop(hash_ctx);
  absorb(hash_ctx, digestLen);
  
  if (hash_ctx->a)
  {
    shuffle(hash_ctx);
  }
  for (i = 0; i < digestLen; i++)
  {
    digest[i] = drip(hash_ctx);
  }
}









void spritz_hash(uint8_t *digest, uint8_t digestLen,
                 const uint8_t *data, uint16_t dataLen)
{
  uint8_t i;
  spritz_ctx hash_ctx;

  
  spritz_state_init(&hash_ctx);

  
  absorbBytes(&hash_ctx, data, dataLen);

  
  absorbStop(&hash_ctx);
  absorb(&hash_ctx, digestLen);
  
  if (hash_ctx.a)
  {
    shuffle(&hash_ctx);
  }
  for (i = 0; i < digestLen; i++)
  {
    digest[i] = drip(&hash_ctx);
  }

  
#ifdef SPRITZ_WIPE_TRACES
  spritz_state_memzero(&hash_ctx);
#endif
}








void spritz_mac_setup(spritz_ctx *mac_ctx,
                      const uint8_t *key, uint16_t keyLen)
{
  spritz_state_init(mac_ctx);        
  absorbBytes(mac_ctx, key, keyLen); 
  absorbStop(mac_ctx);
}








void spritz_mac_update(spritz_ctx *mac_ctx,
                       const uint8_t *msg, uint16_t msgLen)
{
  absorbBytes(mac_ctx, msg, msgLen); 
}








void spritz_mac_final(spritz_ctx *mac_ctx,
                      uint8_t *digest, uint8_t digestLen)
{
  
  uint8_t i;

  absorbStop(mac_ctx);
  absorb(mac_ctx, digestLen);
  
  if (mac_ctx->a)
  {
    shuffle(mac_ctx);
  }
  for (i = 0; i < digestLen; i++)
  {
    digest[i] = drip(mac_ctx);
  }
}











void spritz_mac(uint8_t *digest, uint8_t digestLen,
                const uint8_t *msg, uint16_t msgLen,
                const uint8_t *key, uint16_t keyLen)
{
  uint8_t i;
  spritz_ctx mac_ctx;

  
  spritz_state_init(&mac_ctx);        
  absorbBytes(&mac_ctx, key, keyLen); 
  absorbStop(&mac_ctx);

  
  absorbBytes(&mac_ctx, msg, msgLen); 

  
  
  absorbStop(&mac_ctx);
  absorb(&mac_ctx, digestLen);
  
  if (mac_ctx.a)
  {
    shuffle(&mac_ctx);
  }
  for (i = 0; i < digestLen; i++)
  {
    digest[i] = drip(&mac_ctx);
  }

  
#ifdef SPRITZ_WIPE_TRACES
  spritz_state_memzero(&mac_ctx);
#endif
}