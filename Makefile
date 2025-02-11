-include .env

.PHONY: all test clean clean-all deploy install snapshot format anvil

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80


all: clean remove install update build

clean  :; forge clean

clean-all :; forge clean && rm -rf broadcast && rm -rf cache

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules

# TODO: This changes the commit of the submodules which we don't want.
# install :; 	forge install foundry-rs/forge-std@v1.8.2 --no-commit && \
# 			forge install openzeppelin/openzeppelin-contracts@v5.0.2 --no-commit && \
# 			forge install openzeppelin/openzeppelin-contracts-upgradeable@v5.0.2 --no-commit && \
# 			forge install symbioticfi/core --no-commit && \
# 			forge install symbioticfi/collateral --no-commit && \
# 			forge install symbioticfi/rewards --no-commit && \
# 			forge install Cyfrin/foundry-devops --no-commit && \
# 			forge install PaulRBerg/prb-math@release-v4 --no-commit&&\
# 			forge install moondance-labs/tanssi-bridge-relayer --no-commit --no-git && \
# 			cd lib/tanssi-bridge-relayer && ./add_overridden_contracts.sh

install :; 	git submodule update --init --recursive && \
			cd lib/tanssi-bridge-relayer && ./add_overridden_contracts.sh


install-tanssi-relayer :; cd lib/tanssi-bridge-relayer && ./add_overridden_contracts.sh

update:; forge update

build:; forge build

test :; forge test

testv :; forge test -vvvv

coverage :; forge coverage --nmp test/fork/*

dcoverage :; forge coverage --nmp test/fork/* --report debug > coverage.txt

snapshot :; forge snapshot --nmp test/fork/*

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_KEY) --broadcast


deploy:
	@echo "🚀 Deploying contracts..."

	@echo "📡 Deploying Collateral..."
	@forge script script/DeployCollateral.s.sol:DeployCollateral ${NETWORK_ARGS}
	@echo "✅ Collateral deployment completed"
	
	@echo "📡 Deploying Symbiotic..."
	@forge script script/DeploySymbiotic.s.sol ${NETWORK_ARGS} --slow --skip-simulation --sig "run(address)" 0x5FbDB2315678afecb367f032d93F642f64180aa3
	@echo "✅ Symbiotic deployment completed"
	
demo:
	@echo "📡 Deploying Demo..."
	@forge script script/Demo.s.sol:Demo ${NETWORK_ARGS} --sig "run(address,address,address,address,address,address)" 0x09635F643e140090A9A8Dcd712eD6285858ceBef 0x5FC8d32690cc91D4c39d9d3abcBD16989F875707 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 0x610178dA211FEF7D417bC0e6FeD39F05609AD788 0x8A791620dd6260079BF849Dc5567aDC3F2FdC318
	@echo "✅ Demo deployment completed"

deploy-tanssi-eco:
	@echo "📡 Deploying Tanssi Ecosystem..."
	@forge script script/DeployTanssiEcosystem.s.sol:DeployTanssiEcosystem ${NETWORK_ARGS} --slow --skip-simulation
	@echo "✅ Tanssi Ecosystem deployment completed"

deploy-full-tanssi-eco-demo:
	@echo "📡 Deploying Full Tanssi Ecosystem Locally for Demo..."
	@forge script script/test/DeployTanssiEcosystemDemo.s.sol --slow --skip-simulation ${NETWORK_ARGS}
	@echo "✅ Full Tanssi Ecosystem Locally for Demo deployment completed"

# EXAMPLE: These are all mock data to deploy locally
# Make example:
# make deploy-rewards VAULT_ADDRESS=0xc5d41F3f9C4930992EE01DDb226bfD7212C00CBA VAULT_FACTORY_ADDRESS=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 ADMIN_FEE=100 DEFAULT_ADMIN_ROLE=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 ADMIN_FEE_CLAIM_ROLE=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 ADMIN_FEE_SET_ROLE=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 NETWORK=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 NETWORK_MIDDLEWARE_SERVICE=0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6 START_TIME=1234567890 EPOCH_DURATION=86400 OPERATOR_SHARE=5000

deploy-rewards:
	@echo "📡 Deploying Rewards Contracts..."
	@forge script script/DeployRewards.s.sol ${NETWORK_ARGS} \
		--sig "run((address,address,uint256,address,address,address,address,address,uint48,uint48,uint48))" \
		"($(VAULT_ADDRESS),$(VAULT_FACTORY_ADDRESS),$(ADMIN_FEE),$(DEFAULT_ADMIN_ROLE),$(ADMIN_FEE_CLAIM_ROLE),$(ADMIN_FEE_SET_ROLE),$(NETWORK),$(NETWORK_MIDDLEWARE_SERVICE),$(START_TIME),$(EPOCH_DURATION),$(OPERATOR_SHARE))"
	@echo "✅ Rewards Contracts deployment completed"