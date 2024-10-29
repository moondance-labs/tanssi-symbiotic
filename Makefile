-include .env

.PHONY: all test clean deploy fund help install snapshot format anvil

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
DEFAULT_OWNER := 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
DEFAULT_VAULT_CONFIGURATOR := 0x4A679253410272dd5232B3Ff7cF5dbB88f295319
DEFAULT_COLLATERAL := 0x5FbDB2315678afecb367f032d93F642f64180aa3


all: clean remove install update build

# Clean the repo
clean  :; forge clean

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules && git add . && git commit -m "modules"

install :; forge install foundry-rs/forge-std@v1.8.2 --no-commit && forge install openzeppelin/openzeppelin-contracts@v5.0.2 --no-commit && forge install openzeppelin/openzeppelin-contracts-upgradeable@v5.0.2 --no-commit && forge install symbioticfi/core --no-commit  && forge install symbioticfi/rewards --no-commit

# Update Dependencies
update:; forge update

build:; forge build

test :; forge test 

snapshot :; forge snapshot

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_KEY) --broadcast
	
deploy-symbiotic:
	@echo "🚀 Deploying contracts..."

	@echo "📡 Deploying Collateral..."
	@forge script script/DeployCollateral.s.sol:DeployCollateral ${NETWORK_ARGS} | tee /dev/tty | grep 'Collateral:' | sed 's/.*Collateral: //' > .collateral
	@echo "Using saved collateral address: $$(cat .collateral)"
	@echo "✅ Collateral deployment completed"

	@echo "📡 Deploying Core..."
	@forge script lib/core/script/deploy/Core.s.sol:CoreScript $(DEFAULT_OWNER) --sig "run(address)" $(NETWORK_ARGS) | tee /dev/tty | grep 'VaultConfigurator:' | sed 's/.*VaultConfigurator: //' > .configurator
	@echo "Using saved configurator address: $$(cat .configurator)"
	@echo "✅ Core deployment completed"

	@echo "📡 Deploying NetworkRegistry..."
	@forge script lib/core/script/deploy/NetworkRegistry.s.sol:NetworkRegistryScript $(NETWORK_ARGS)
	@echo "✅ NetworkRegistry deployment completed"

	@echo "📡 Deploying MetadataService..."
	@forge script lib/core/script/deploy/MetadataService.s.sol:MetadataServiceScript ${DEFAULT_OWNER} --sig "run(address)" $(NETWORK_ARGS)
	@echo "✅ MetadataService deployment completed"

	@echo "📡 Deploying NetworkMiddlewareService..."
	@forge script lib/core/script/deploy/NetworkMiddlewareService.s.sol:NetworkMiddlewareServiceScript ${DEFAULT_OWNER} --sig "run(address)" $(NETWORK_ARGS)
	@echo "✅ NetworkMiddlewareService deployment completed"

	@echo "📡 Deploying OptInService..."
	@forge script lib/core/script/deploy/OptInService.s.sol:OptInServiceScript ${DEFAULT_OWNER} ${DEFAULT_OWNER} "test" --sig "run(address,address,string)" $(NETWORK_ARGS)
	@echo "✅ OptInService deployment completed"

	@echo "📡 Deploying OperatorRegistry..."
	@forge script lib/core/script/deploy/OperatorRegistry.s.sol:OperatorRegistryScript $(NETWORK_ARGS)
	@echo "✅ OperatorRegistry deployment completed"

	@echo "📡 Deploying VaultFactory..."
	@forge script lib/core/script/deploy/VaultFactory.s.sol:VaultFactoryScript ${DEFAULT_OWNER} --sig "run(address)" ${NETWORK_ARGS}
	@echo "✅ VaultFactory deployment completed"

	@echo "📡 Deploying Vault..."
	@forge script lib/core/script/deploy/Vault.s.sol:VaultScript \
		$$(cat .configurator) \
		${DEFAULT_OWNER} \
		$$(cat .collateral) \
		1 false 0 0 false 0 0 \
		--sig "run(address,address,address,uint48,bool,uint256,uint64,bool,uint64,uint48)" ${NETWORK_ARGS}
	@echo "✅ Vault deployment completed"

	@echo "📡 Deploying VaultVetoed..."
	@forge script lib/core/script/deploy/Vault.s.sol:VaultScript \
		$$(cat .configurator) \
	  	${DEFAULT_OWNER} \
	   	$$(cat .collateral) \
		1 false 0 0 true 1 0 \
		--sig "run(address,address,address,uint48,bool,uint256,uint64,bool,uint64,uint48)" ${NETWORK_ARGS}
	@echo "✅ VaultVetoed deployment completed"

	@echo "📡 Deploying VaultTokenized..."
	@forge script lib/core/script/deploy/VaultTokenized.s.sol:VaultTokenizedScript \
		$$(cat .configurator) \
	  	${DEFAULT_OWNER} \
	   	$$(cat .collateral) \
	    1 false 0 Test TEST 0 false 0 0 \
		--sig "run(address,address,address,uint48,bool,uint256,string,string,uint64,bool,uint64,uint48)" ${NETWORK_ARGS}
	@echo "✅ VaultTokenized deployment completed"

	@rm -f .collateral .configurator

