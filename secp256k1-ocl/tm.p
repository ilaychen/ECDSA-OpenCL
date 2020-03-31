./configure:    ECDSA_verify(0, NULL, 0, NULL, 0, eckey);
Binary file ./tests matches
./.git/hooks/pre-commit.sample:# An example hook script to verify what is about to be committed.
./.git/hooks/pre-commit.sample:if git rev-parse --verify HEAD >/dev/null 2>&1
./.git/hooks/pre-push.sample:# An example hook script to verify what is about to be pushed.  Called by "git
./.git/hooks/pre-applypatch.sample:# An example hook script to verify what is about to be committed
./.git/packed-refs:21f81a846957408d4a2fe30cff32370567887a93 refs/remotes/origin/verify
./.git/packed-refs:03d84a427fe5099db91aef0e6e0263fb458629f2 refs/remotes/origin/verify_openssl
Binary file ./.git/index matches
Binary file ./.git/objects/pack/pack-8241bdce793dd64e7168d25eb4618d394e87d8a7.pack matches
./Makefile:#am__append_1 = bench_verify bench_sign bench_internal
./Makefile:##am__append_10 = bench_schnorr_verify
./Makefile:#am__EXEEXT_1 = bench_verify$(EXEEXT) \
./Makefile:##am__EXEEXT_4 = bench_schnorr_verify$(EXEEXT)
./Makefile:am__bench_schnorr_verify_SOURCES_DIST = src/bench_schnorr_verify.c
./Makefile:##am_bench_schnorr_verify_OBJECTS = src/bench_schnorr_verify.$(OBJEXT)
./Makefile:bench_schnorr_verify_OBJECTS = $(am_bench_schnorr_verify_OBJECTS)
./Makefile:##bench_schnorr_verify_DEPENDENCIES = libsecp256k1.la \
./Makefile:am__bench_verify_SOURCES_DIST = src/bench_verify.c
./Makefile:#am_bench_verify_OBJECTS =  \
./Makefile:#	src/bench_verify.$(OBJEXT)
./Makefile:bench_verify_OBJECTS = $(am_bench_verify_OBJECTS)
./Makefile:#bench_verify_DEPENDENCIES = libsecp256k1.la \
./Makefile:	$(bench_schnorr_verify_SOURCES) $(bench_sign_SOURCES) \
./Makefile:	$(bench_verify_SOURCES) $(tests_SOURCES)
./Makefile:	$(am__bench_schnorr_verify_SOURCES_DIST) \
./Makefile:	$(am__bench_verify_SOURCES_DIST) $(am__tests_SOURCES_DIST)
./Makefile:#bench_verify_SOURCES = src/bench_verify.c
./Makefile:#bench_verify_LDADD = libsecp256k1.la $(SECP_LIBS)
./Makefile:##bench_schnorr_verify_SOURCES = src/bench_schnorr_verify.c
./Makefile:##bench_schnorr_verify_LDADD = libsecp256k1.la $(SECP_LIBS)
./Makefile:src/bench_schnorr_verify.$(OBJEXT): src/$(am__dirstamp) \
./Makefile:bench_schnorr_verify$(EXEEXT): $(bench_schnorr_verify_OBJECTS) $(bench_schnorr_verify_DEPENDENCIES) $(EXTRA_bench_schnorr_verify_DEPENDENCIES) 
./Makefile:	@rm -f bench_schnorr_verify$(EXEEXT)
./Makefile:	$(AM_V_CCLD)$(LINK) $(bench_schnorr_verify_OBJECTS) $(bench_schnorr_verify_LDADD) $(LIBS)
./Makefile:src/bench_verify.$(OBJEXT): src/$(am__dirstamp) \
./Makefile:bench_verify$(EXEEXT): $(bench_verify_OBJECTS) $(bench_verify_DEPENDENCIES) $(EXTRA_bench_verify_DEPENDENCIES) 
./Makefile:	@rm -f bench_verify$(EXEEXT)
./Makefile:	$(AM_V_CCLD)$(LINK) $(bench_verify_OBJECTS) $(bench_verify_LDADD) $(LIBS)
./Makefile:include src/$(DEPDIR)/bench_schnorr_verify.Po
./Makefile:include src/$(DEPDIR)/bench_verify.Po
./Makefile.in:@USE_BENCHMARK_TRUE@am__append_1 = bench_verify bench_sign bench_internal
./Makefile.in:@ENABLE_MODULE_SCHNORR_TRUE@@USE_BENCHMARK_TRUE@am__append_10 = bench_schnorr_verify
./Makefile.in:@USE_BENCHMARK_TRUE@am__EXEEXT_1 = bench_verify$(EXEEXT) \
./Makefile.in:@ENABLE_MODULE_SCHNORR_TRUE@@USE_BENCHMARK_TRUE@am__EXEEXT_4 = bench_schnorr_verify$(EXEEXT)
./Makefile.in:am__bench_schnorr_verify_SOURCES_DIST = src/bench_schnorr_verify.c
./Makefile.in:@ENABLE_MODULE_SCHNORR_TRUE@@USE_BENCHMARK_TRUE@am_bench_schnorr_verify_OBJECTS = src/bench_schnorr_verify.$(OBJEXT)
./Makefile.in:bench_schnorr_verify_OBJECTS = $(am_bench_schnorr_verify_OBJECTS)
./Makefile.in:@ENABLE_MODULE_SCHNORR_TRUE@@USE_BENCHMARK_TRUE@bench_schnorr_verify_DEPENDENCIES = libsecp256k1.la \
./Makefile.in:am__bench_verify_SOURCES_DIST = src/bench_verify.c
./Makefile.in:@USE_BENCHMARK_TRUE@am_bench_verify_OBJECTS =  \
./Makefile.in:@USE_BENCHMARK_TRUE@	src/bench_verify.$(OBJEXT)
./Makefile.in:bench_verify_OBJECTS = $(am_bench_verify_OBJECTS)
./Makefile.in:@USE_BENCHMARK_TRUE@bench_verify_DEPENDENCIES = libsecp256k1.la \
./Makefile.in:	$(bench_schnorr_verify_SOURCES) $(bench_sign_SOURCES) \
./Makefile.in:	$(bench_verify_SOURCES) $(tests_SOURCES)
./Makefile.in:	$(am__bench_schnorr_verify_SOURCES_DIST) \
./Makefile.in:	$(am__bench_verify_SOURCES_DIST) $(am__tests_SOURCES_DIST)
./Makefile.in:@USE_BENCHMARK_TRUE@bench_verify_SOURCES = src/bench_verify.c
./Makefile.in:@USE_BENCHMARK_TRUE@bench_verify_LDADD = libsecp256k1.la $(SECP_LIBS)
./Makefile.in:@ENABLE_MODULE_SCHNORR_TRUE@@USE_BENCHMARK_TRUE@bench_schnorr_verify_SOURCES = src/bench_schnorr_verify.c
./Makefile.in:@ENABLE_MODULE_SCHNORR_TRUE@@USE_BENCHMARK_TRUE@bench_schnorr_verify_LDADD = libsecp256k1.la $(SECP_LIBS)
./Makefile.in:src/bench_schnorr_verify.$(OBJEXT): src/$(am__dirstamp) \
./Makefile.in:bench_schnorr_verify$(EXEEXT): $(bench_schnorr_verify_OBJECTS) $(bench_schnorr_verify_DEPENDENCIES) $(EXTRA_bench_schnorr_verify_DEPENDENCIES) 
./Makefile.in:	@rm -f bench_schnorr_verify$(EXEEXT)
./Makefile.in:	$(AM_V_CCLD)$(LINK) $(bench_schnorr_verify_OBJECTS) $(bench_schnorr_verify_LDADD) $(LIBS)
./Makefile.in:src/bench_verify.$(OBJEXT): src/$(am__dirstamp) \
./Makefile.in:bench_verify$(EXEEXT): $(bench_verify_OBJECTS) $(bench_verify_DEPENDENCIES) $(EXTRA_bench_verify_DEPENDENCIES) 
./Makefile.in:	@rm -f bench_verify$(EXEEXT)
./Makefile.in:	$(AM_V_CCLD)$(LINK) $(bench_verify_OBJECTS) $(bench_verify_LDADD) $(LIBS)
./Makefile.in:@AMDEP_TRUE@@am__include@ @am__quote@src/$(DEPDIR)/bench_schnorr_verify.Po@am__quote@
./Makefile.in:@AMDEP_TRUE@@am__include@ @am__quote@src/$(DEPDIR)/bench_verify.Po@am__quote@
./include/secp256k1_schnorr.h: *           pubkey:    the public key to verify with (cannot be NULL)
./include/secp256k1_schnorr.h:SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorr_verify(
./include/secp256k1_schnorr.h: *  verifiable using secp256k1_schnorr_verify.
./include/secp256k1_schnorr.h: * - The resulting signature is validatable using secp256k1_schnorr_verify, with
./include/secp256k1.h: *           pubkey:    pointer to an initialized public key to verify with (cannot be NULL)
./include/secp256k1.h:SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_verify(
./include/secp256k1.h: * verify, making it a good choice. Security of always using lower-S is
./include/secp256k1.h:SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_seckey_verify(
./src/ecdsa_impl.h:static int secp256k1_ecdsa_sig_verify(const secp256k1_ecmult_context *ctx, const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
./src/tests.c:    /* try verifying */
./src/tests.c:    CHECK(secp256k1_ecdsa_sig_verify(&vrfy->ecmult_ctx, &sigr, &sigs, &pub, &msg));
./src/tests.c:    CHECK(secp256k1_ecdsa_sig_verify(&both->ecmult_ctx, &sigr, &sigs, &pub, &msg));
./src/tests.c:        /* verify */
./src/tests.c:void test_ecdsa_sign_verify(void) {
./src/tests.c:    CHECK(secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &pub, &msg));
./src/tests.c:    CHECK(!secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &pub, &msg));
./src/tests.c:void run_ecdsa_sign_verify(void) {
./src/tests.c:        test_ecdsa_sign_verify();
./src/tests.c:    /* Construct and verify corresponding public key. */
./src/tests.c:    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
./src/tests.c:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
./src/tests.c:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[1], message, &pubkey) == 1);
./src/tests.c:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[2], message, &pubkey) == 1);
./src/tests.c:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[3], message, &pubkey) == 1);
./src/tests.c:    /* Serialize/parse DER and verify again */
./src/tests.c:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
./src/tests.c:    /* Serialize/destroy/parse DER and verify again. */
./src/tests.c:          secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 0);
./src/tests.c:        CHECK(secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sr, &ss, &key, &msg) == 0);
./src/tests.c:    CHECK(secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &q, &msg));
./src/tests.c:    CHECK(!secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &q, &msg2));
./src/tests.c:    CHECK(ECDSA_verify(0, message, sizeof(message), signature, secp_sigsize, ec_key) == 1);
./src/tests.c:    run_ecdsa_sign_verify();
./src/bench_schnorr_verify.c:} benchmark_schnorr_verify_t;
./src/bench_schnorr_verify.c:    benchmark_schnorr_verify_t* data = (benchmark_schnorr_verify_t*)arg;
./src/bench_schnorr_verify.c:static void benchmark_schnorr_verify(void* arg) {
./src/bench_schnorr_verify.c:    benchmark_schnorr_verify_t* data = (benchmark_schnorr_verify_t*)arg;
./src/bench_schnorr_verify.c:        CHECK(secp256k1_schnorr_verify(data->ctx, data->sigs[0].sig, data->msg, &pubkey) == ((i & 0xFF) == 0));
./src/bench_schnorr_verify.c:    benchmark_schnorr_verify_t data;
./src/bench_schnorr_verify.c:    run_benchmark("schnorr_verify", benchmark_schnorr_verify, benchmark_schnorr_init, NULL, &data, 10, 20000);
./src/field_10x26_impl.h:static void secp256k1_fe_verify(const secp256k1_fe *a) {
./src/field_10x26_impl.h:static void secp256k1_fe_verify(const secp256k1_fe *a) {
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(b);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(b);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/field_10x26_impl.h:    secp256k1_fe_verify(a);
./src/field_10x26_impl.h:    secp256k1_fe_verify(r);
./src/modules/schnorr/schnorr_impl.h: * Rationale for verifying R's y coordinate:
./src/modules/schnorr/schnorr_impl.h:static int secp256k1_schnorr_sig_verify(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, const secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
./src/modules/schnorr/tests_impl.h:    /* Construct and verify corresponding public key. */
./src/modules/schnorr/tests_impl.h:    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
./src/modules/schnorr/tests_impl.h:    CHECK(secp256k1_schnorr_verify(ctx, schnorr_signature, message, &pubkey) == 1);
./src/modules/schnorr/tests_impl.h:    /* Destroy signature and verify again. */
./src/modules/schnorr/tests_impl.h:    CHECK(secp256k1_schnorr_verify(ctx, schnorr_signature, message, &pubkey) == 0);
./src/modules/schnorr/tests_impl.h:void test_schnorr_sign_verify(void) {
./src/modules/schnorr/tests_impl.h:        CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64[k], &pubkey[k], &test_schnorr_hash, msg32));
./src/modules/schnorr/tests_impl.h:            CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64[k], &pubkey[k], &test_schnorr_hash, msg32) == 0);
./src/modules/schnorr/tests_impl.h:        } while (!secp256k1_ec_seckey_verify(ctx, sec[i]));
./src/modules/schnorr/tests_impl.h:        ret |= (secp256k1_schnorr_verify(ctx, allsig, msg, &allpub) != 1) * 8;
./src/modules/schnorr/tests_impl.h:        CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64, &Q, &test_schnorr_hash, msg32) == 1);
./src/modules/schnorr/tests_impl.h:         test_schnorr_sign_verify();
./src/modules/schnorr/schnorr.h:static int secp256k1_schnorr_sig_verify(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, const secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32);
./src/modules/schnorr/main_impl.h:int secp256k1_schnorr_verify(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
./src/modules/schnorr/main_impl.h:    return secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64, &q, secp256k1_schnorr_msghash_sha256, msg32);
./src/modules/schnorr/Makefile.am.include:noinst_PROGRAMS += bench_schnorr_verify
./src/modules/schnorr/Makefile.am.include:bench_schnorr_verify_SOURCES = src/bench_schnorr_verify.c
./src/modules/schnorr/Makefile.am.include:bench_schnorr_verify_LDADD = libsecp256k1.la $(SECP_LIBS)
./src/modules/recovery/tests_impl.h:    /* Construct and verify corresponding public key. */
./src/modules/recovery/tests_impl.h:    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
./src/modules/recovery/tests_impl.h:    /* Serialize/parse compact and verify/recover. */
./src/modules/recovery/tests_impl.h:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[4], message, &pubkey) == 1);
./src/modules/recovery/tests_impl.h:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[4], message, &pubkey) == 1);
./src/modules/recovery/tests_impl.h:    /* Serialize/destroy/parse signature and verify again. */
./src/modules/recovery/tests_impl.h:    CHECK(secp256k1_ecdsa_verify(ctx, &signature[4], message, &pubkey) == 0);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyb) == 1);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyb) == 1);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyb) == 1);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyb) == 1);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyb) == 1);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyb) == 0);
./src/modules/recovery/tests_impl.h:                CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbder, sizeof(sigbder)) == 0 || secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyb) == 0);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyc) == 1);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyc) == 0);
./src/modules/recovery/tests_impl.h:        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg32, &pubkeyc) == 0);
Binary file ./src/libsecp256k1_la-secp256k1.o matches
./src/secp256k1.c:int secp256k1_ecdsa_verify(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
./src/secp256k1.c:            secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &q, &m));
./src/secp256k1.c:int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey) {
./src/bench_internal.c:void bench_context_verify(void* arg) {
./src/bench_internal.c:    if (have_flag(argc, argv, "context") || have_flag(argc, argv, "verify")) run_benchmark("context_verify", bench_context_verify, bench_setup, NULL, &data, 10, 20);
./src/java/org_bitcoin_NativeSecp256k1.c:JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
./src/java/org_bitcoin_NativeSecp256k1.c:	return secp256k1_ecdsa_verify(data, 32, data+32+8, sigLen, data+32+8+sigLen, pubLen);
./src/java/org/bitcoin/NativeSecp256k1.java:    public static boolean verify(byte[] data, byte[] signature, byte[] pub) {
./src/java/org/bitcoin/NativeSecp256k1.java:        return secp256k1_ecdsa_verify(byteBuff) == 1;
./src/java/org/bitcoin/NativeSecp256k1.java:    private static native int secp256k1_ecdsa_verify(ByteBuffer byteBuff);
./src/java/org_bitcoin_NativeSecp256k1.h: * Method:    secp256k1_ecdsa_verify
./src/java/org_bitcoin_NativeSecp256k1.h:JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
./src/bench_verify.c:} benchmark_verify_t;
./src/bench_verify.c:static void benchmark_verify(void* arg) {
./src/bench_verify.c:    benchmark_verify_t* data = (benchmark_verify_t*)arg;
./src/bench_verify.c:        CHECK(secp256k1_ecdsa_verify(data->ctx, &sig, data->msg, &pubkey) == (i == 0));
./src/bench_verify.c:    benchmark_verify_t data;
./src/bench_verify.c:    run_benchmark("ecdsa_verify", benchmark_verify, NULL, NULL, &data, 10, 20000);
Binary file ./src/.libs/libsecp256k1_la-secp256k1.o matches
Binary file ./src/tests-tests.o matches
./src/ecdsa.h:static int secp256k1_ecdsa_sig_verify(const secp256k1_ecmult_context *ctx, const secp256k1_scalar* r, const secp256k1_scalar* s, const secp256k1_ge *pubkey, const secp256k1_scalar *message);
./src/field_5x52_impl.h:static void secp256k1_fe_verify(const secp256k1_fe *a) {
./src/field_5x52_impl.h:static void secp256k1_fe_verify(const secp256k1_fe *a) {
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(b);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(b);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./src/field_5x52_impl.h:    secp256k1_fe_verify(a);
./src/field_5x52_impl.h:    secp256k1_fe_verify(r);
./config.log:Configured with: ../src/configure -v --with-pkgversion='Ubuntu 5.4.0-6ubuntu1~16.04.11' --with-bugurl=file:///usr/share/doc/gcc-5/README.Bugs --enable-languages=c,ada,c++,java,go,d,fortran,objc,obj-c++ --prefix=/usr --program-suffix=-5 --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-libmpx --enable-plugin --with-system-zlib --disable-browser-plugin --enable-java-awt=gtk --enable-gtk-cairo --with-java-home=/usr/lib/jvm/java-1.5.0-gcj-5-amd64/jre --enable-java-home --with-jvm-root-dir=/usr/lib/jvm/java-1.5.0-gcj-5-amd64 --with-jvm-jar-dir=/usr/lib/jvm-exports/java-1.5.0-gcj-5-amd64 --with-arch-directory=amd64 --with-ecj-jar=/usr/share/java/eclipse-ecj.jar --enable-objc-gc --enable-multiarch --disable-werror --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
./config.log:Configured with: ../src/configure -v --with-pkgversion='Ubuntu 5.4.0-6ubuntu1~16.04.11' --with-bugurl=file:///usr/share/doc/gcc-5/README.Bugs --enable-languages=c,ada,c++,java,go,d,fortran,objc,obj-c++ --prefix=/usr --program-suffix=-5 --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-libmpx --enable-plugin --with-system-zlib --disable-browser-plugin --enable-java-awt=gtk --enable-gtk-cairo --with-java-home=/usr/lib/jvm/java-1.5.0-gcj-5-amd64/jre --enable-java-home --with-jvm-root-dir=/usr/lib/jvm/java-1.5.0-gcj-5-amd64 --with-jvm-jar-dir=/usr/lib/jvm-exports/java-1.5.0-gcj-5-amd64 --with-arch-directory=amd64 --with-ecj-jar=/usr/share/java/eclipse-ecj.jar --enable-objc-gc --enable-multiarch --disable-werror --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
./Makefile.am:noinst_PROGRAMS += bench_verify bench_sign bench_internal
./Makefile.am:bench_verify_SOURCES = src/bench_verify.c
./Makefile.am:bench_verify_LDADD = libsecp256k1.la $(SECP_LIBS)
./build-aux/ltmain.sh:	# Possibly a libtool archive, so verify it.
./build-aux/ltmain.sh:	# Possibly a libtool object, so verify it.
./build-aux/m4/bitcoin_secp.m4:    ECDSA_verify(0, NULL, 0, NULL, 0, eckey);
Binary file ./.libs/libsecp256k1.so.0.0.0 matches
Binary file ./.libs/libsecp256k1.a matches
./autom4te.cache/output.2:    ECDSA_verify(0, NULL, 0, NULL, 0, eckey);
./autom4te.cache/output.1:    ECDSA_verify(0, NULL, 0, NULL, 0, eckey);
./autom4te.cache/output.0:    ECDSA_verify(0, NULL, 0, NULL, 0, eckey);
./autom4te.cache/traces.2:    ECDSA_verify(0, NULL, 0, NULL, 0, eckey);
./autom4te.cache/traces.0:    ECDSA_verify(0, NULL, 0, NULL, 0, eckey);
./.gitignore:bench_verify
./.gitignore:bench_schnorr_verify
./libtool:	# Possibly a libtool archive, so verify it.
./libtool:	# Possibly a libtool object, so verify it.
