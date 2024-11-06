import { ethers } from "ethers";
import { NETWORK_PRIVATE_KEY, RESOLVER_PRIVATE_KEY } from "../../config";
import { VetoSlasherAPI } from "./veto_slasher";
import { subnetwork } from "../../utils";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const networkWallet = new ethers.Wallet(NETWORK_PRIVATE_KEY, jsonProvider);
const resolverWallet = new ethers.Wallet(RESOLVER_PRIVATE_KEY, jsonProvider);

const VETO_SLASHER_CONTRACT_ADDRESS =
  "0x02129319612dE494175D7962DC4F0A8b3dAE8d5b";

const OPERATOR_ADDRESS = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const vetoSlasher = new VetoSlasherAPI(
  VETO_SLASHER_CONTRACT_ADDRESS,
  networkWallet
);

vetoSlasher.slashRequestsLength().then((length) => {
  console.log("Slash requests length: ", length.toString());
});

const subNetwork = subnetwork(networkWallet.address, 0);

const requestSlashAndVeto = async () => {
  const resolver = await vetoSlasher.resolver(subNetwork, "0x");
  console.log("Resolver: ", resolver);

  const vault = await vetoSlasher.vault();
  console.log("Vault: ", vault);

  const slashableStake = await vetoSlasher.slashableStake({
    subnetwork: subNetwork,
    operator: OPERATOR_ADDRESS,
    captureTimestamp: Date.now() - 1000 * 60 * 1000,
    hints: "0x",
  });
  console.log("Slashable Stake: ", slashableStake.toString());

  await vetoSlasher.setResolver(0, resolverWallet.address, "0x");

  // This can be called only by middleware, leaving here for reference
  const slashIndex = await vetoSlasher.requestSlash({
    subnetwork: subNetwork,
    operator: OPERATOR_ADDRESS,
    amount: ethers.BigNumber.from(1000),
    hints: "0x",
    captureTimestamp: Date.now(),
  });
  await vetoSlasher.vetoSlash({ slashIndex, hints: "" });
};

requestSlashAndVeto();
