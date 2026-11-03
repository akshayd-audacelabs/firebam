NANOPB_GEN?=nanopb_generator.py

PROTOS:=
PROTOS+=astralane_relayer

.PHONY: generate
generate: $(addsuffix .pb.h,$(PROTOS)) $(addsuffix .pb.c,$(PROTOS))

# Imports packet/shared/bundle from the bundle tile's generated protos.
%.pb.h %.pb.c: %.proto %.options
	$(NANOPB_GEN) --protoc-opt=--experimental_allow_proto3_optional -I. -I../../bundle/proto --options-file $(patsubst %.proto,%.options,$<) $<
	sed -i 's|#include <pb.h>|#include "../../../third_party/nanopb/pb_firedancer.h"|' $(patsubst %.proto,%.pb.h,$<)
	sed -i 's@#include "\(packet\|shared\|bundle\|timestamp\).pb.h"@#include "../../bundle/proto/\1.pb.h"@' $(patsubst %.proto,%.pb.h,$<)

.PHONY: clean
clean:
	rm -f $(addsuffix .pb.h,$(PROTOS)) $(addsuffix .pb.c,$(PROTOS))
