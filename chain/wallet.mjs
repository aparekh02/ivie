// viem clients bound to zknet. All transactions are signed locally and sent
// with eth_sendRawTransaction, exactly as a wallet would on mainnet. Nothing
// relies on anvil's unlocked accounts.
import { createPublicClient, createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';

// anvil's well-known dev keys (public; never use on a real network)
export const KEYS = [
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
];

export function clients(url, keyIndex = 0) {
  const chain = { ...mainnet, rpcUrls: { default: { http: [url] } } };
  const transport = http(url, { timeout: 60_000 });
  const account = privateKeyToAccount(KEYS[keyIndex]);
  return {
    account,
    pub: createPublicClient({ chain, transport, pollingInterval: 250 }),
    wallet: createWalletClient({ chain, transport, account }),
  };
}
