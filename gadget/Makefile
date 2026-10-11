IMAGE ?= ghcr.io/vfalico/ig-kmx-guardd-public/agentpolicy:0.4.1
IG ?= ig

.PHONY: test vet build inspect

test:
	go test ./...

vet:
	go vet ./...

build: test vet
	$(IG) image build --builder-image-pull=missing --update-metadata --validate-metadata -t $(IMAGE) .

inspect:
	$(IG) image inspect --verify-image=false --pull=never $(IMAGE)
