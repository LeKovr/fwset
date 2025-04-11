## template Makefile:
## service example
#:

SHELL          = /bin/sh
CFG           ?= .env
CFG_TMPL      ?= Makefile.env
PRG           ?= $(shell basename $$PWD)

# -----------------------------------------------------------------------------
# Docker image config

#- App name
APP_NAME      ?= $(PRG)

#- Docker-compose project name (container name prefix)
PROJECT_NAME  ?= $(PRG)

# Hardcoded in docker-compose.yml service name
DC_SERVICE    ?= app

#- Docker image name
IMAGE         ?= $(DOCKER_IMAGE)

#- Docker image tag
IMAGE_VER     ?= latest

# -----------------------------------------------------------------------------
# App config

-include $(CFG_TMPL)

# ------------------------------------------------------------------------------
-include $(CFG).bak
-include $(CFG)
export

include Makefile.golang

# Find and include DCAPE/apps/drone/dcape-app/Makefile
DCAPE_COMPOSE ?= dcape-compose
DCAPE_ROOT    ?= $(shell docker inspect -f "{{.Config.Labels.dcape_root}}" $(DCAPE_COMPOSE))

ifeq ($(shell test -e $(DCAPE_ROOT)/Makefile.app && echo -n yes),yes)
  include $(DCAPE_ROOT)/Makefile.app
endif


.PHONY: buildall dist clean docker docker-multi use-own-hub godoc ghcr

# ------------------------------------------------------------------------------
## Docker build operations
#:

# build docker image directly
docker: $(PRG)
	docker build -t $(PRG) .

ALLARCH_DOCKER ?= "linux/amd64,linux/arm/v7,linux/arm64"

# build multiarch docker images via buildx
docker-multi:
	time docker buildx build --platform $(ALLARCH_DOCKER) -t $(DOCKER_IMAGE):$(APP_VERSION) --push .

# ------------------------------------------------------------------------------
## Other
#:

## update docs at pkg.go.dev
godoc:
	vf=$(APP_VERSION) ; v=$${vf%%-*} ; echo "Update for $$v..." ; \
	curl 'https://proxy.golang.org/$(GODOC_REPO)/@v/'$$v'.info'

## update latest docker image tag at ghcr.io
ghcr:
	v=$(APP_VERSION) ; echo "Update for $$v..." ; \
	docker pull $(DOCKER_IMAGE):$$v && \
	docker tag $(DOCKER_IMAGE):$$v $(DOCKER_IMAGE):latest && \
	docker push $(DOCKER_IMAGE):latest
