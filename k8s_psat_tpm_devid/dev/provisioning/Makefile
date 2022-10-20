.DEFAULT_GOAL := help

GOOS=linux
GOARCH=amd64
OUT_DIR=out
SHELL=/bin/bash
DEFAULT_TPM_SOCKET?="/tmp/swtpm.sock"
DEFAULT_TPM_STATE?="../manufacture-tpm/output/tpm2-00.permall"

## Builds the provisioning tool binaries
build: clean
	git clone https://github.com/HewlettPackard/devid-provisioning-tool.git
	(cd devid-provisioning-tool; git reset --hard b912ef2c19571093dfacd0a6721dd1e6f6299768)
	(cd devid-provisioning-tool; make build)

	mkdir $(OUT_DIR)
	cp devid-provisioning-tool/bin/**/* $(OUT_DIR)/


## Cleans provisioning tool temporary files
clean:
	if [ -d devid-provisioning-tool ]; then rm -rf devid-provisioning-tool; fi
	if [ -d $(OUT_DIR) ]; then rm -rf $(OUT_DIR); fi


## Setups provisioning tool certificates
setup-provisioning:
	@echo "Creating self-signed provisioning CA key and certificate..."
	openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj '/' \
		-addext "subjectAltName = DNS:provisioning-ca" \
		-keyout conf/server/provisioning-ca.key \
		-out conf/server/provisioning-ca.crt

	@echo "Creating self-signed server CA key and certificate..."
	openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj '/' \
		-addext "subjectAltName = DNS:server-ca" \
		-keyout conf/server/server-ca.key \
		-out conf/server/server-ca.crt
		
	@echo "Creating server key and certificate signed by server CA..."
	@# Create server key
	openssl req -newkey rsa:2048 -nodes -x509 -days 365 -subj '/' \
		-addext "subjectAltName = DNS:localhost" \
		-keyout conf/server/server.key

	@# Creates CSR
	openssl req -new -key conf/server/server.key -subj '/' -extensions SAN -reqexts SAN \
		-config <(cat /etc/ssl/openssl.cnf <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
		-out server.csr

	@# Signs server certificate
	openssl x509 -req -days 365 -in server.csr \
		-CA conf/server/server-ca.crt -CAkey conf/server/server-ca.key -CAcreateserial \
		-extfile <(printf 'subjectAltName=DNS:localhost') \
		-out conf/server/server.crt

	rm -f server.csr server.srl


## Setups and runs swtpm in a container
run-swtpm: clean-swtpm
	git clone https://github.com/marcosy/swtpm-container.git
	(cd swtpm-container; git reset --hard 3317c944b61067bba95e5638a1fd23d0642284fd)
	(cd swtpm-container/manufacture-tpm; ./run.sh)
	(cd swtpm-container/run-tpm; ./run.sh $(DEFAULT_TPM_STATE) $(DEFAULT_TPM_SOCKET))


## Cleans swtmp temporary files and kills any running container
clean-swtpm:
	docker container stop swtpm > /dev/null 2>&1 || true
	if [ -d swtpm-container ]; then rm -rf swtpm-container; fi


## Runs provisioning server in foreground
provisioning-server: $(OUT_DIR)/provisioning-server
	./$(OUT_DIR)/provisioning-server


## Runs provisioning agent
provisioning-agent: $(OUT_DIR)/provisioning-agent
	./$(OUT_DIR)/provisioning-agent -tpmPath=$(DEFAULT_TPM_SOCKET)
	@printf "\nDevID certificates are in '$(OUT_DIR)'\n\n"


#------------------------------------------------------------------------
# Automatic help generator
#------------------------------------------------------------------------

# COLORS
GREEN := $(shell tput -Txterm setaf 2)
RESET := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=22
AUTHOR=HPE Security Engineering
NAME = TPM Provisioning tools


## Shows help
help:
	@echo "--------------------------------------------------------------------------------"
	@echo "Author  : ${GREEN}$(AUTHOR)${RESET}"
	@echo "Project : ${GREEN}$(NAME)${RESET}"
	@echo "--------------------------------------------------------------------------------"
	@echo ""
	@echo "Usage:"
	@echo "  ${GREEN}make${RESET} <target>"
	@echo "Targets:"
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "  ${GREEN}%-$(TARGET_MAX_CHAR_NUM)s${RESET} %s\n", helpCommand, helpMessage; \
		} \
	} \
{ lastLine = $$0 }' $(MAKEFILE_LIST)
