ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_precnf_encode.h fd_precnf_auth.h fd_precnf_client.h)
$(call add-objs,fd_precnf_encode fd_precnf_auth fd_precnf_client fd_precnf_tile,fd_disco)

$(call make-unit-test,test_precnf_encode,test_precnf_encode,fd_disco fd_ballet fd_util)
$(call run-unit-test,test_precnf_encode)
endif
