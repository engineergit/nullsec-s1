"""Web3 examples: wallet transaction risk and smart-contract risk."""
from corpus.builder import vuln

EXAMPLES = [
    # ---- wallet transaction risk ----
    vuln(
        id="wallet-unbounded-transfer",
        lang="javascript", framework="solana-web3.js", file="pay.js", line=2,
        code=(
            "async function pay(to, lamports) {\n"
            "  const tx = new Transaction().add(SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: to, lamports }));\n"
            "  return sendAndConfirm(tx, [wallet]); // no cap, no confirmation\n"
            "}\n"
        ),
        category="WALLET_TRANSACTION_RISK",
        description="Transfer signs an arbitrary amount to an arbitrary recipient with no cap or confirmation.",
        exploit="A bug or injected call passes the full balance / attacker address and drains the wallet.",
        fix="Enforce a per-transaction cap and an allowlist/confirmation before signing.",
        patch="+  if (lamports > MAX_LAMPORTS) throw new Error('exceeds per-tx cap');\n+  if (!ALLOWED_RECIPIENTS.has(to.toBase58())) throw new Error('recipient not allowed');\n   const tx = new Transaction().add(SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: to, lamports }));",
    ),
    vuln(
        id="wallet-blind-sign",
        lang="javascript", framework="ethers", file="sign.js", line=2,
        code=(
            "async function approve(spender) {\n"
            "  return token.approve(spender, ethers.MaxUint256); // infinite approval\n"
            "}\n"
        ),
        category="WALLET_TRANSACTION_RISK",
        description="Grants unlimited (MaxUint256) token approval to a spender.",
        exploit="A malicious or compromised spender contract transfers the entire token balance at any later time.",
        fix="Approve only the exact amount needed and revoke afterward.",
        patch="-  return token.approve(spender, ethers.MaxUint256);\n+  return token.approve(spender, requiredAmount);",
    ),
    vuln(
        id="wallet-no-sim",
        lang="python", framework="solana-py", file="bot.py", line=2,
        code=(
            "def execute(tx):\n"
            "    return client.send_transaction(tx, keypair)  # no simulation, no slippage guard\n"
        ),
        category="WALLET_TRANSACTION_RISK",
        description="Trading bot sends transactions without simulation or slippage protection.",
        exploit="A sandwich/MEV attack or stale price executes a swap at a catastrophic rate.",
        fix="Simulate first, enforce a minimum-out / slippage bound, and abort on adverse simulation.",
        patch="-    return client.send_transaction(tx, keypair)\n+    sim = client.simulate_transaction(tx)\n+    if sim.value.err or below_min_out(sim): raise RuntimeError('unsafe execution')\n+    return client.send_transaction(tx, keypair)",
    ),
    # ---- smart contract risk ----
    vuln(
        id="sc-reentrancy",
        lang="solidity", framework="solidity-foundry", file="Vault.sol", line=3,
        code=(
            "function withdraw(uint amt) external {\n"
            "    require(balance[msg.sender] >= amt);\n"
            "    (bool ok,) = msg.sender.call{value: amt}('');\n"
            "    balance[msg.sender] -= amt;   // state updated AFTER external call\n"
            "}\n"
        ),
        category="SMART_CONTRACT_RISK",
        description="Reentrancy: external call precedes the balance update.",
        exploit="A malicious receiver re-enters withdraw() before the balance decrements, draining the vault.",
        fix="Apply checks-effects-interactions or a reentrancy guard; update state before the call.",
        patch="     require(balance[msg.sender] >= amt);\n+    balance[msg.sender] -= amt;\n     (bool ok,) = msg.sender.call{value: amt}('');\n-    balance[msg.sender] -= amt;",
    ),
    vuln(
        id="sc-missing-access-control",
        lang="solidity", framework="hardhat", file="Token.sol", line=2,
        code=(
            "function mint(address to, uint amt) external {\n"
            "    _mint(to, amt);   // anyone can mint\n"
            "}\n"
        ),
        category="SMART_CONTRACT_RISK",
        description="mint() has no access control.",
        exploit="Any caller mints unlimited tokens to themselves, destroying the token's value.",
        fix="Restrict to an owner/minter role.",
        patch="-function mint(address to, uint amt) external {\n+function mint(address to, uint amt) external onlyOwner {\n     _mint(to, amt);\n }",
        fail_dims=("permissions",),
    ),
    vuln(
        id="sc-unchecked-transfer",
        lang="solidity", framework="solidity-foundry", file="Payout.sol", line=2,
        code=(
            "function payout(address token, address to, uint amt) external {\n"
            "    IERC20(token).transfer(to, amt);  // return value ignored\n"
            "}\n"
        ),
        category="SMART_CONTRACT_RISK",
        description="ERC20 transfer return value ignored; some tokens return false instead of reverting.",
        exploit="With a non-reverting token, a failed transfer is treated as success, corrupting accounting.",
        fix="Use SafeERC20 / check the boolean return.",
        patch="-    IERC20(token).transfer(to, amt);\n+    IERC20(token).safeTransfer(to, amt);",
        severity="MEDIUM",
    ),
]
