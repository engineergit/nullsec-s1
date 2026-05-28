// swap.ts
// VULNERABLE EXAMPLE — an unbounded ("infinite") ERC-20 approval granted to a
// spender address that is taken from a URL parameter. This is a classic
// AI-generated Web3 frontend mistake.

import { ethers } from "ethers";

const MAX_UINT256 = ethers.MaxUint256;

export async function approveSpender(
  token: ethers.Contract,
  // DANGER: spender comes straight from the page URL, unvalidated.
  spenderFromUrl: string,
) {
  // Unlimited approval to an arbitrary, attacker-influenced address. If the
  // spender is malicious (or later compromised), it can drain the entire token
  // balance at any time, with no per-transaction cap and no expiry.
  const tx = await token.approve(spenderFromUrl, MAX_UINT256);
  return tx.wait();
}
