./configure:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./configure:  as_bourne_compatible="if test -n \"\${ZSH_VERSION+set}\" && (emulate sh) >/dev/null 2>&1; then :
./configure:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./src/ecdsa_impl.h:static int secp256k1_ecdsa_sig_verify(const secp256k1_ecmult_context *ctx, const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
./src/ecdsa_impl.h:static int secp256k1_ecdsa_sig_recover(const secp256k1_ecmult_context *ctx, const secp256k1_scalar *sigr, const secp256k1_scalar* sigs, secp256k1_ge *pubkey, const secp256k1_scalar *message, int recid) {
./src/ecdsa_impl.h:static int secp256k1_ecdsa_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid) {
./src/tests.c:void run_ecmult_chain(void) {
./src/tests.c:void ecmult_const_random_mult(void) {
./src/tests.c:void ecmult_const_commutativity(void) {
./src/tests.c:void ecmult_const_mult_zero_one(void) {
./src/tests.c:void ecmult_const_chain_multiply(void) {
./src/tests.c:void run_ecmult_const_tests(void) {
./src/tests.c:void test_ecmult_constants(void) {
./src/tests.c:void run_ecmult_constants(void) {
./src/tests.c:void test_ecmult_gen_blind(void) {
./src/tests.c:void test_ecmult_gen_blind_reset(void) {
./src/tests.c:void run_ecmult_gen_blind(void) {
./src/ecmult_impl.h:static void secp256k1_ecmult_odd_multiples_table(int n, secp256k1_gej *prej, secp256k1_fe *zr, const secp256k1_gej *a) {
./src/ecmult_impl.h:static void secp256k1_ecmult_odd_multiples_table_globalz_windowa(secp256k1_ge *pre, secp256k1_fe *globalz, const secp256k1_gej *a) {
./src/ecmult_impl.h:static void secp256k1_ecmult_odd_multiples_table_storage_var(int n, secp256k1_ge_storage *pre, const secp256k1_gej *a, const secp256k1_callback *cb) {
./src/ecmult_impl.h:static void secp256k1_ecmult_context_init(secp256k1_ecmult_context *ctx) {
./src/ecmult_impl.h:static void secp256k1_ecmult_context_build(secp256k1_ecmult_context *ctx, const secp256k1_callback *cb) {
./src/ecmult_impl.h:static int secp256k1_ecmult_context_is_built(const secp256k1_ecmult_context *ctx) {
./src/ecmult_impl.h:static void secp256k1_ecmult_context_clear(secp256k1_ecmult_context *ctx) {
./src/ecmult_impl.h:static int secp256k1_ecmult_wnaf(int *wnaf, int len, const secp256k1_scalar *a, int w) {
./src/ecmult_impl.h:static void secp256k1_ecmult(const secp256k1_ecmult_context *ctx, secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
./src/field_10x26_impl.h:SECP256K1_INLINE static void secp256k1_fe_mul_int(secp256k1_fe *r, int a) {
./src/field_10x26_impl.h:SECP256K1_INLINE static void secp256k1_fe_mul_inner(uint32_t *r, const uint32_t *a, const uint32_t * SECP256K1_RESTRICT b) {
./src/field_10x26_impl.h:static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
./src/gen_context.c:    fprintf(fp, "static const secp256k1_ge_storage secp256k1_ecmult_static_context[64][16] = {\n");
./src/modules/schnorr/schnorr_impl.h:static int secp256k1_schnorr_sig_sign(const secp256k1_ecmult_gen_context* ctx, unsigned char *sig64, const secp256k1_scalar *key, const secp256k1_scalar *nonce, const secp256k1_ge *pubnonce, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
./src/modules/schnorr/schnorr_impl.h:static int secp256k1_schnorr_sig_verify(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, const secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
./src/modules/schnorr/schnorr_impl.h:static int secp256k1_schnorr_sig_recover(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
./src/modules/schnorr/tests_impl.h:            if (secp256k1_schnorr_sig_sign(&ctx->ecmult_gen_ctx, sig64[k], &key[k], &nonce[k], NULL, &test_schnorr_hash, msg32)) {
./src/modules/schnorr/tests_impl.h:    if (secp256k1_schnorr_sig_recover(&ctx->ecmult_ctx, sig64, &Q, &test_schnorr_hash, msg32) == 1) {
./src/modules/schnorr/main_impl.h:            if (secp256k1_schnorr_sig_sign(&ctx->ecmult_gen_ctx, sig64, &sec, &non, NULL, secp256k1_schnorr_msghash_sha256, msg32)) {
./src/modules/schnorr/main_impl.h:    if (secp256k1_schnorr_sig_recover(&ctx->ecmult_ctx, sig64, &q, secp256k1_schnorr_msghash_sha256, msg32)) {
./src/modules/recovery/main_impl.h:                if (secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, &recid)) {
./src/modules/recovery/main_impl.h:    if (secp256k1_ecdsa_sig_recover(&ctx->ecmult_ctx, &r, &s, &q, &m, recid)) {
./src/field_5x52_asm_impl.h:SECP256K1_INLINE static void secp256k1_fe_mul_inner(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b) {
./src/ecmult_gen_impl.h:static void secp256k1_ecmult_gen_context_init(secp256k1_ecmult_gen_context *ctx) {
./src/ecmult_gen_impl.h:static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx, const secp256k1_callback* cb) {
./src/ecmult_gen_impl.h:static int secp256k1_ecmult_gen_context_is_built(const secp256k1_ecmult_gen_context* ctx) {
./src/ecmult_gen_impl.h:static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
./src/ecmult_gen_impl.h:static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
./src/ecmult_gen_impl.h:static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
./src/secp256k1.c:                if (secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, NULL)) {
./src/secp256k1.c:int secp256k1_ec_privkey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
./src/secp256k1.c:int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak) {
./src/bench_internal.c:void bench_scalar_mul(void* arg) {
./src/bench_internal.c:void bench_field_mul(void* arg) {
./src/bench_internal.c:void bench_ecmult_wnaf(void* arg) {
./src/ecmult_const_impl.h:static void secp256k1_ecmult_const(secp256k1_gej *r, const secp256k1_ge *a, const secp256k1_scalar *scalar) {
./src/scalar_8x32_impl.h:#define muladd(a,b) { \
./src/scalar_8x32_impl.h:#define muladd_fast(a,b) { \
./src/scalar_8x32_impl.h:#define muladd2(a,b) { \
./src/scalar_8x32_impl.h:static void secp256k1_scalar_mul_512(uint32_t *l, const secp256k1_scalar *a, const secp256k1_scalar *b) {
./src/scalar_8x32_impl.h:static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
./src/scalar_8x32_impl.h:SECP256K1_INLINE static void secp256k1_scalar_mul_shift_var(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, unsigned int shift) {
./src/num_gmp_impl.h:static void secp256k1_num_mul(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b) {
./src/eckey_impl.h:static int secp256k1_eckey_privkey_serialize(const secp256k1_ecmult_gen_context *ctx, unsigned char *privkey, size_t *privkeylen, const secp256k1_scalar *key, unsigned int flags) {
./src/eckey_impl.h:static int secp256k1_eckey_pubkey_tweak_add(const secp256k1_ecmult_context *ctx, secp256k1_ge *key, const secp256k1_scalar *tweak) {
./src/eckey_impl.h:static int secp256k1_eckey_privkey_tweak_mul(secp256k1_scalar *key, const secp256k1_scalar *tweak) {
./src/eckey_impl.h:static int secp256k1_eckey_pubkey_tweak_mul(const secp256k1_ecmult_context *ctx, secp256k1_ge *key, const secp256k1_scalar *tweak) {
./src/scalar_4x64_impl.h:#define muladd(a,b) { \
./src/scalar_4x64_impl.h:#define muladd_fast(a,b) { \
./src/scalar_4x64_impl.h:#define muladd2(a,b) { \
./src/scalar_4x64_impl.h:static void secp256k1_scalar_mul_512(uint64_t l[8], const secp256k1_scalar *a, const secp256k1_scalar *b) {
./src/scalar_4x64_impl.h:static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
./src/scalar_4x64_impl.h:SECP256K1_INLINE static void secp256k1_scalar_mul_shift_var(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, unsigned int shift) {
./src/group_impl.h:static void secp256k1_ge_mul_lambda(secp256k1_ge *r, const secp256k1_ge *a) {
./src/field_5x52_impl.h:SECP256K1_INLINE static void secp256k1_fe_mul_int(secp256k1_fe *r, int a) {
./src/field_5x52_impl.h:static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
./src/field_5x52_int128_impl.h:SECP256K1_INLINE static void secp256k1_fe_mul_inner(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b) {
./config.status:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./tm.p:./src/ecdsa_impl.h:static int secp256k1_ecdsa_sig_verify(const secp256k1_ecmult_context *ctx, const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
./tm.p:./src/modules/schnorr/schnorr_impl.h:static int secp256k1_schnorr_sig_verify(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, const secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
./build-aux/ltmain.sh:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./build-aux/ltmain.sh:if test -n \"\${ZSH_VERSION+set}\" && (emulate sh) >/dev/null 2>&1; then
./autom4te.cache/output.2:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.2:  as_bourne_compatible="if test -n \"\${ZSH_VERSION+set}\" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.2:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.1:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.1:  as_bourne_compatible="if test -n \"\${ZSH_VERSION+set}\" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.1:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.0:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.0:  as_bourne_compatible="if test -n \"\${ZSH_VERSION+set}\" && (emulate sh) >/dev/null 2>&1; then :
./autom4te.cache/output.0:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./libtool:if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then :
./libtool:if test -n \"\${ZSH_VERSION+set}\" && (emulate sh) >/dev/null 2>&1; then
