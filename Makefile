-include .env

.PHONY: all test clean deploy fund help install snapshot format anvil

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80


all: clean remove install update build

# Clean the repo
clean  :; forge clean

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules

install :; 	forge install foundry-rs/forge-std@v1.8.2 --no-commit && \
		 	forge install openzeppelin/openzeppelin-contracts@v5.0.2 --no-commit && \
			forge install openzeppelin/openzeppelin-contracts-upgradeable@v5.0.2 --no-commit && \
			forge install symbioticfi/core --no-commit  && \
			forge install symbioticfi/rewards --no-commit && \
			forge install Cyfrin/foundry-devops --no-commit

# Update Dependencies
update:; forge update

build:; forge build

test :; forge test

testv :; forge test -vvvv

coverage :; forge coverage

snapshot :; forge snapshot

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_KEY) --broadcast

deploy:
	@echo "🚀 Deploying contracts..."

	@echo "📡 Deploying Collateral..."
	@forge script script/DeployCollateral.s.sol:DeployCollateral ${NETWORK_ARGS}
	@echo "✅ Collateral deployment completed"

	@echo "📡 Deploying Symbiotic..."
	@forge script script/DeploySymbiotic.s.sol ${NETWORK_ARGS}
	@echo "✅ Symbiotic deployment completed"
