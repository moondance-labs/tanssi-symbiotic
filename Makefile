-include .env

.PHONY: all test clean clean-all deploy install snapshot format anvil pre-deploy

DEFAULT_ANVIL_KEY := 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6


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
# 			forge install symbioticfi/middleware-sdk --no-commit && \
# 			forge install Cyfrin/foundry-devops --no-commit && \
# 			forge install PaulRBerg/prb-math@release-v4 --no-commit && \
# 			forge install moondance-labs/snowbridge --no-git

install :; 	git submodule update --init --recursive

update:; forge update

build:; forge build

test :; forge test

testv :; forge test -vvvv

coverage :; forge coverage --nmp "test/fork/*"

coverage-fork-testnet :; forge coverage --mp "test/fork/*" --nmp "test/fork/mainnet/Full.t.sol" --fork-url ${SEPOLIA_RPC_URL} -vvv

coverage-fork-mainnet :; forge coverage --mp "test/fork/mainnet/Full.t.sol" --fork-url ${ETH_RPC_URL} -vvv

dcoverage :; forge coverage --nmp "test/fork/*" --report debug > coverage.txt

hcoverage:; forge coverage  --nmp "test/fork/*" --report lcov && genhtml lcov.info -o report --branch-coverage

snapshot :; forge snapshot --nmp "test/fork/*"

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

RPC_URL ?= http://localhost:8545
PRIVATE_KEY ?= ${DEFAULT_ANVIL_KEY}
GAS_PRICE = 2000000000 # 2 Gwei
ADDITIONAL_ARGS_BASE = --account mainnetDeployer --sender 0x008f37a7307aba7d5d9bca771c4a56f853755d1f --with-gas-price $(GAS_PRICE)

# Flag: set to 1 to use private key, 0 to use base args
USE_PRIVATE_KEY ?= 1

ifeq ($(USE_PRIVATE_KEY),1)
  ADDITIONAL_ARGS = --private-key $(PRIVATE_KEY)
else
  ADDITIONAL_ARGS = $(ADDITIONAL_ARGS_BASE)
endif
NETWORK_ARGS := --rpc-url ${RPC_URL} --broadcast --verify --etherscan-api-key ${ETHERSCAN_API_KEY} ${ADDITIONAL_ARGS}

pre-deploy:
	@echo "🧹 Cleaning forge artifacts..."
	@forge clean

deploy-full-tanssi-eco-demo: pre-deploy
	@echo "📡 Deploying Full Tanssi Ecosystem Locally for Demo..."
	@forge script demos/DeployTanssiEcosystemDemo.s.sol --slow --skip-simulation ${NETWORK_ARGS}
	@echo "✅ Full Tanssi Ecosystem Locally for Demo deployment completed"

deploy-full-tanssi-eco: pre-deploy
	@echo "📡 Deploying Full Tanssi Ecosystem..."
	@forge script script/DeployProduction.s.sol:DeployProduction $(NETWORK_ARGS) --sig "deploy()" -vv
	@echo "✅ Full Tanssi Ecosystem deployment completed"

deploy-operator-rewards: pre-deploy
	@echo "📡 Deploying Operator Rewards..."
	@forge script script/DeployRewards.s.sol:DeployRewards $(NETWORK_ARGS) --sig "deployOperatorRewardsContract(address,address,uint48,address)" $(NETWORK) $(NETWORK_MIDDLEWARE_SERVICE) $(OPERATOR_SHARE) $(ADMIN_ADDRESS) -vv
	@echo "✅ Operator Rewards deployment completed"

deploy-staker-rewards-factory: pre-deploy
	@echo "📡 Deploying Staker Rewards Factory..."
	@forge script script/DeployRewards.s.sol:DeployRewards $(NETWORK_ARGS) --sig "deployStakerRewardsFactoryContract(address,address,address,address,address)" $(VAULT_FACTORY_ADDRESS) $(NETWORK_MIDDLEWARE_SERVICE) $(OPERATOR_REWARDS_PROXY_ADDRESS) $(NETWORK) $(ADMIN_ADDRESS) -vv
	@echo "✅ Staker Rewards Factory deployment completed"

deploy-tanssi-vault: pre-deploy
	@echo "📡 Deploying Tanssi Vault..."
	@forge script script/DeployVault.s.sol:DeployVault $(NETWORK_ARGS) --sig "createTanssiVault(address,address,address)" $(VAULT_CONFIGURATOR_ADDRESS) $(ADMIN_ADDRESS) $(TOKEN_ADDRESS) -vv
	@echo "✅ Tanssi Vault deployment completed"

deploy-middleware: pre-deploy
	@echo "📡 Deploying Middleware Implementation..."
	@forge script script/DeployTanssiEcosystem.s.sol:DeployTanssiEcosystem $(NETWORK_ARGS) --sig "deployOnlyMiddleware(bool)" $(SHOULD_DEPLOY_READER) --optimize true --optimizer-runs 800 -vv
	@echo "✅ Middleware Implementation deployment completed"

deploy-staker-rewards: pre-deploy
	@echo "📡 Deploying Staker Rewards Implementation..."
	@forge script script/DeployRewards.s.sol:DeployRewards $(NETWORK_ARGS) --sig "deployStakerRewards(address,address)" $(NETWORK_MIDDLEWARE_SERVICE) $(NETWORK) -vv
	@echo "✅ Staker Rewards Implementation deployment completed"

upgrade-middleware: pre-deploy
	@echo "📡 Upgrading Middleware..."
	@forge script script/DeployTanssiEcosystem.s.sol $(NETWORK_ARGS) --sig "upgradeMiddlewareBroadcast(address,uint256)" $(MIDDLEWARE_ADDRESS) $(CURRENT_MIDDLEWARE_VERSION) -vv
	@echo "✅ Middleware upgrade completed"

upgrade-operator-rewards: pre-deploy
	@echo "📡 Upgrading Operator Rewards..."
	@forge script script/DeployRewards.s.sol:DeployRewards $(NETWORK_ARGS) --sig "upgradeOperatorRewards(address,address,address)" $(OPERATOR_REWARDS_PROXY_ADDRESS) $(NETWORK) $(NETWORK_MIDDLEWARE_SERVICE) -vv
	@echo "✅ Operator Rewards upgrade completed"
	
deploy-dia-aggregator-oracle-proxy: pre-deploy
	@echo "📡 Deploying DIA Aggregator Oracle Proxy..."
	@forge script script/DeployTanssiEcosystem.s.sol:DeployTanssiEcosystem $(NETWORK_ARGS) --sig "deployDIAAggregatorOracleProxy(address,string)" $(DIA_ORACLE_ADDRESS) $(PAIR_SYMBOL) -vv
	@echo "✅ DIA Aggregator Oracle Proxy deployment completed"

deploy-reader: pre-deploy
	@echo "📡 Deploying Middleware Reader..."
	@forge script script/DeployTanssiEcosystem.s.sol:DeployTanssiEcosystem $(NETWORK_ARGS) --sig "deployMiddlewareReader()" -vv
	@echo "✅ Middleware Reader deployment completed"

deploy-rewards-hints-builder: pre-deploy
	@echo "📡 Deploying Rewards Hints Builder..."
	@forge script script/DeployRewards.s.sol:DeployRewards $(NETWORK_ARGS) --sig "deployRewardsHintsBuilder(address,address,address)" $(MIDDLEWARE_ADDRESS) $(OPERATOR_REWARDS_PROXY_ADDRESS) $(VAULT_HINTS_ADDRESS) -vv
	@echo "✅ Rewards Hints Builder deployment completed"