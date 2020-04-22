
go: test/fuzz/init-token.fuzz.c
	clang -o go -g -I src/lib -I src -I test -fsanitize=address,fuzzer test/fuzz/init-token.fuzz.c ./src/.libs/libtpm2_test_pkcs11.a -Wl,--wrap=Esys_Initialize -Wl,--wrap=backend_fapi_init -Wl,--wrap=Tss2_TctiLdr_Initialize, -Wl,--wrap=Tss2_TctiLdr_Finalize -Wl,--wrap=Esys_GetCapability -Wl,--wrap=Esys_TestParms -Wl,--wrap=Esys_Finalize -Wl,--wrap=Esys_TR_FromTPMPublic -Wl,--wrap=Esys_TR_Serialize -Wl,--wrap=Esys_TR_Deserialize -Wl,--wrap=Esys_TR_SetAuth -Wl,--wrap=Esys_StartAuthSession -Wl,--wrap=Esys_TRSess_SetAttributes -Wl,--wrap=Esys_TRSess_GetAttributes -Wl,--wrap=Esys_CreateLoaded -Wl,--wrap=Esys_Create -Wl,--wrap=Esys_FlushContext -L./src/.libs -ltpm2_pkcs11 -lcrypto -lyaml -ltss2-esys -ltss2-mu -lcmocka -ltss2-tctildr -ltss2-rc -lsqlite3 -ltss2-fapi
clean:
	rm go
