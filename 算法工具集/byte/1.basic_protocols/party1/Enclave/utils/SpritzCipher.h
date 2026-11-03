
















#ifndef SPRITZCIPHER_H
#define SPRITZCIPHER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h> 





#if 0
#define SPRITZ_USE_LIBC
#include <string.h>                           
#if !defined(__GNUC__) && !defined(__clang__) 
#warning "SPRITZ_USE_LIBC warning: Code optimization isn't off in some security functions."
#endif 
#endif





#if 1
#define SPRITZ_TIMING_SAFE_CRUSH
#endif






#if 0
#define SPRITZ_WIPE_TRACES
#endif










#if 0
#define SPRITZ_WIPE_TRACES_PARANOID
#endif

#ifdef SPRITZ_WIPE_TRACES_PARANOID
#ifndef SPRITZ_TIMING_SAFE_CRUSH
#define SPRITZ_TIMING_SAFE_CRUSH
#endif
#ifndef SPRITZ_WIPE_TRACES
#define SPRITZ_WIPE_TRACES
#endif
#endif





#define SPRITZ_N 256U


#define SPRITZ_LIBRARY_VERSION_STRING "1.2.0"
#define SPRITZ_LIBRARY_VERSION_MAJOR 1
#define SPRITZ_LIBRARY_VERSION_MINOR 2
#define SPRITZ_LIBRARY_VERSION_PATCH 0

  


  typedef struct
  {
    uint8_t s[SPRITZ_N];
    uint8_t i, j, k, z, a, w;
#ifdef SPRITZ_WIPE_TRACES_PARANOID
    


    uint8_t tmp1, tmp2;
#endif
  } spritz_ctx;

  











  uint8_t
  spritz_compare(const uint8_t *data_a, const uint8_t *data_b, uint16_t len);

  





  void
  spritz_memzero(uint8_t *buf, uint16_t len);

  




  void
  spritz_state_memzero(spritz_ctx *ctx);

  






  void
  spritz_setup(spritz_ctx *ctx,
               const uint8_t *key, uint8_t keyLen);

  
  
  

  








  void
  spritz_setup_withIV(spritz_ctx *ctx,
                      const uint8_t *key, uint8_t keyLen,
                      const uint8_t *nonce, uint8_t nonceLen);

  







  uint8_t
  spritz_random8(spritz_ctx *ctx);

  







  uint32_t
  spritz_random32(spritz_ctx *ctx);

  uint64_t
  spritz_random64(spritz_ctx *ctx);

  

  void
  spritz_random64_flush(spritz_ctx *ctx);

  
















  uint32_t
  spritz_random32_uniform(spritz_ctx *ctx, uint32_t upper_bound);

  







  void
  spritz_add_entropy(spritz_ctx *ctx,
                     const uint8_t *entropy, uint16_t len);

  








  void
  spritz_crypt(spritz_ctx *ctx,
               const uint8_t *data, uint16_t dataLen,
               uint8_t *dataOut);

  








  void
  spritz_crypt_inplace(spritz_ctx *ctx,
                       uint8_t *data, uint16_t dataLen);

  




  void
  spritz_hash_setup(spritz_ctx *hash_ctx);

  






  void
  spritz_hash_update(spritz_ctx *hash_ctx,
                     const uint8_t *data, uint16_t dataLen);

  






  void
  spritz_hash_final(spritz_ctx *hash_ctx,
                    uint8_t *digest, uint8_t digestLen);

  







  void
  spritz_hash(uint8_t *digest, uint8_t digestLen,
              const uint8_t *data, uint16_t dataLen);

  






  void
  spritz_mac_setup(spritz_ctx *mac_ctx,
                   const uint8_t *key, uint16_t keyLen);

  






  void
  spritz_mac_update(spritz_ctx *mac_ctx,
                    const uint8_t *msg, uint16_t msgLen);

  






  void
  spritz_mac_final(spritz_ctx *mac_ctx,
                   uint8_t *digest, uint8_t digestLen);

  









  void
  spritz_mac(uint8_t *digest, uint8_t digestLen,
             const uint8_t *msg, uint16_t msgLen,
             const uint8_t *key, uint16_t keyLen);

#ifdef __cplusplus
}
#endif

#endif 