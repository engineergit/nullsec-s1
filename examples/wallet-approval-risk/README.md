# Example — Unsafe wallet approval (unbounded ERC-20 approve)

**File:** [`approve.ts`](approve.ts) · **Category:** `WALLET_TRANSACTION_RISK` · **Failing dimension:** `secrets`

A generated Web3 frontend grants an **infinite** ERC-20 approval
(`MaxUint256`) to a spender address read **straight from the URL**. This is one of
the most damaging patterns in AI-generated dApps.

> In the Nullsec taxonomy, `WALLET_TRANSACTION_RISK` maps to the `secrets` check
> dimension, so the Safety Layer marks `secrets` as `fail` for this finding.

## Why it is unsafe

- **Unlimited allowance:** the spender can move the user's entire token balance,
  not just the amount needed for one swap.
- **Untrusted spender:** the address comes from a URL parameter an attacker can
  craft.
- **No expiry / no cap:** the approval persists indefinitely.

## Expected category

`WALLET_TRANSACTION_RISK` (default severity **CRITICAL**, CWE-798 / CWE-840).

## Expected verdict (illustrative — not model output)

```jsonc
{
  "production_ready": false,        // Safety Layer: R2 (secrets=fail) + R3 (CRITICAL)
  "severity": "CRITICAL",
  "checks_performed": {
    "secrets": { "status": "fail", "note": "unbounded approval to URL-controlled spender" }
  },
  "findings": [
    { "category": "WALLET_TRANSACTION_RISK", "severity": "CRITICAL", "file": "approve.ts", "line": 18 }
  ]
}
```

## Exploit scenario

An attacker shares a link with `?spender=0xAttacker`. The dApp approves unlimited
spend to that address. The attacker later calls `transferFrom` and drains the
victim's entire token balance.

## Secure patch direction

Approve only the **exact amount** needed, to a **validated, known** spender, and
prefer EIP-2612 `permit` with an expiry when available.

```ts
const KNOWN_ROUTER = "0xKnownRouterAddress"; // from config, not the URL

export async function approveSpender(token: ethers.Contract, amount: bigint) {
  // Exact-amount approval to a trusted router only.
  const tx = await token.approve(KNOWN_ROUTER, amount);
  return tx.wait();
}
```

Validate spender addresses against an allowlist, surface the approved amount in
the UI, and never derive a spender from untrusted input.
