"""
Built-in database of known 4-byte function selectors and their metadata.

All selector values are pre-computed: keccak256(signature)[0:4].
No external API or network call is needed at runtime.

Format: selector_hex -> {name, sig, risk, reason, category}
  risk:     "low" | "medium" | "high"
  category: "ownership" | "proxy" | "auth" | "key_material" | "signer_set" |
            "config" | "debug" | "erc_standard" | "multisig" | "timelock" | "diamond"
"""

from __future__ import annotations

import hashlib
import struct
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _keccak256(data: bytes) -> bytes:
    """
    Compute Ethereum's keccak-256 hash.
    Tries pycryptodome first, then sha3 (pysha3/eth_hash), then raises.
    """
    # pycryptodome / pycryptodomex
    try:
        from Crypto.Hash import keccak as _keccak  # type: ignore
        k = _keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        pass
    # pysha3 (pip install pysha3)
    try:
        import sha3 as _sha3  # type: ignore  # noqa: F401
        import hashlib as _hl
        return _hl.new("sha3_256", data).digest()  # NOTE: pysha3 patches hashlib
    except ImportError:
        pass
    raise RuntimeError(
        "keccak-256 not available: install pycryptodome or pysha3.\n"
        "  pip install pycryptodome"
    )


def selector_of(sig: str) -> str:
    """Return '0x' + first-4-bytes hex of keccak256(sig)."""
    digest = _keccak256(sig.encode())
    return "0x" + digest[:4].hex()


# ---------------------------------------------------------------------------
# Pre-computed selector database
# ---------------------------------------------------------------------------
# These values were computed with keccak256 offline and are stable.

SELECTOR_DB: Dict[str, Dict] = {

    # ----- Ownership / Admin -----------------------------------------------

    "0x8da5cb5b": {
        "name": "owner",
        "sig": "owner()",
        "risk": "low",
        "reason": "Exposes the privileged owner address",
        "category": "ownership",
    },
    "0xf851a440": {
        "name": "admin",
        "sig": "admin()",
        "risk": "medium",
        "reason": "Exposes the admin address — often controls upgrades",
        "category": "ownership",
    },
    "0x893d20e8": {
        "name": "getOwner",
        "sig": "getOwner()",
        "risk": "low",
        "reason": "Exposes the privileged owner address",
        "category": "ownership",
    },
    "0xe30c3978": {
        "name": "pendingOwner",
        "sig": "pendingOwner()",
        "risk": "low",
        "reason": "Reveals the pending ownership transfer target",
        "category": "ownership",
    },
    "0x53a47bb7": {
        "name": "nominatedOwner",
        "sig": "nominatedOwner()",
        "risk": "low",
        "reason": "Reveals the nominated (pending) owner",
        "category": "ownership",
    },
    "0x6e9960c3": {
        "name": "getAdmin",
        "sig": "getAdmin()",
        "risk": "medium",
        "reason": "Exposes the admin address",
        "category": "ownership",
    },
    "0x26782247": {
        "name": "pendingAdmin",
        "sig": "pendingAdmin()",
        "risk": "low",
        "reason": "Reveals the pending admin transfer target",
        "category": "ownership",
    },
    "0xd784d426": {
        "name": "adminAddress",
        "sig": "adminAddress()",
        "risk": "medium",
        "reason": "Exposes the admin/governance address",
        "category": "ownership",
    },

    # ----- Proxy / Implementation ------------------------------------------

    "0x5c60da1b": {
        "name": "implementation",
        "sig": "implementation()",
        "risk": "low",
        "reason": "Exposes the proxy implementation address (EIP-1967 / ERC-897)",
        "category": "proxy",
    },
    "0xaaf10f42": {
        "name": "getImplementation",
        "sig": "getImplementation()",
        "risk": "low",
        "reason": "Exposes the proxy implementation address",
        "category": "proxy",
    },
    "0xd784d426": {
        "name": "adminAddress",
        "sig": "adminAddress()",
        "risk": "medium",
        "reason": "Proxy admin address — controls upgrades",
        "category": "proxy",
    },
    "0x4555d5c9": {
        "name": "proxyType",
        "sig": "proxyType()",
        "risk": "low",
        "reason": "ERC-897 proxy type indicator",
        "category": "proxy",
    },
    "0xd4b83992": {
        "name": "target",
        "sig": "target()",
        "risk": "low",
        "reason": "Exposes the proxy target/delegate address",
        "category": "proxy",
    },
    "0x3659cfe6": {
        "name": "upgradeTo",
        "sig": "upgradeTo(address)",
        "risk": "medium",
        "reason": "Upgrade entry point — reveals upgradeability",
        "category": "proxy",
    },

    # ----- Auth / Signers / Validators -------------------------------------

    "0x452a9320": {
        "name": "guardian",
        "sig": "guardian()",
        "risk": "high",
        "reason": "Exposes the guardian/recovery address — high-value target",
        "category": "auth",
    },
    "0xd19a83e2": {
        "name": "getGuardian",
        "sig": "getGuardian()",
        "risk": "high",
        "reason": "Exposes the guardian address",
        "category": "auth",
    },
    "0xa0e67e2b": {
        "name": "getOwners",
        "sig": "getOwners()",
        "risk": "medium",
        "reason": "Exposes all Safe/multisig owner addresses",
        "category": "multisig",
    },
    "0xe75235b8": {
        "name": "getThreshold",
        "sig": "getThreshold()",
        "risk": "low",
        "reason": "Reveals multisig threshold — useful for attack planning",
        "category": "multisig",
    },
    "0xcc2f8452": {
        "name": "getModules",
        "sig": "getModules()",
        "risk": "medium",
        "reason": "Exposes all Gnosis Safe modules — shows attack surface",
        "category": "multisig",
    },
    "0x2f54bf6e": {
        "name": "isOwner",
        "sig": "isOwner(address)",
        "risk": "low",
        "reason": "Allows enumeration of owners",
        "category": "multisig",
    },
    "0x9c7c3b74": {
        "name": "getSigner",
        "sig": "getSigner(uint256)",
        "risk": "high",
        "reason": "Exposes a specific signer address — enables targeting of signers",
        "category": "signer_set",
    },
    "0x6d94b9fd": {
        "name": "getSigners",
        "sig": "getSigners()",
        "risk": "high",
        "reason": "Exposes the full signer set — high-value for social engineering",
        "category": "signer_set",
    },
    "0x35aa2e44": {
        "name": "signers",
        "sig": "signers(uint256)",
        "risk": "high",
        "reason": "Public signer array exposes all signing keys",
        "category": "signer_set",
    },

    # ----- Key material / Secrets ------------------------------------------

    "0x1998aeef": {
        "name": "secret",
        "sig": "secret()",
        "risk": "high",
        "reason": "Function named 'secret' — almost certainly sensitive",
        "category": "key_material",
    },
    "0x9e2bf22e": {
        "name": "seed",
        "sig": "seed()",
        "risk": "high",
        "reason": "Exposes a seed value — may be used in key derivation",
        "category": "key_material",
    },
    "0xe47d6060": {
        "name": "getSecret",
        "sig": "getSecret()",
        "risk": "high",
        "reason": "Getter for secret — almost certainly sensitive",
        "category": "key_material",
    },
    "0xa2fb9e2e": {
        "name": "getMnemonic",
        "sig": "getMnemonic()",
        "risk": "high",
        "reason": "Exposes mnemonic phrase — catastrophic if true",
        "category": "key_material",
    },
    "0x11fd06a1": {
        "name": "privateKey",
        "sig": "privateKey()",
        "risk": "high",
        "reason": "Exposes a private key — catastrophic",
        "category": "key_material",
    },
    "0x5c658165": {
        "name": "getPrivateKey",
        "sig": "getPrivateKey()",
        "risk": "high",
        "reason": "Getter for private key — catastrophic if true",
        "category": "key_material",
    },
    "0x10fe9ae8": {
        "name": "getMerkleRoot",
        "sig": "getMerkleRoot()",
        "risk": "medium",
        "reason": "Exposes Merkle root — may allow allow-list bypass construction",
        "category": "auth",
    },
    "0x2eb4a7ab": {
        "name": "merkleRoot",
        "sig": "merkleRoot()",
        "risk": "medium",
        "reason": "Public Merkle root — may allow allow-list bypass construction",
        "category": "auth",
    },

    # ----- Config / Operational --------------------------------------------

    "0x0dbe671f": {
        "name": "getFee",
        "sig": "getFee()",
        "risk": "low",
        "reason": "Exposes fee configuration — useful for MEV/attack planning",
        "category": "config",
    },
    "0x7af548c5": {
        "name": "getConfig",
        "sig": "getConfig()",
        "risk": "medium",
        "reason": "Generic config getter may expose privileged addresses",
        "category": "config",
    },
    "0x3e47158c": {
        "name": "relayer",
        "sig": "relayer()",
        "risk": "medium",
        "reason": "Exposes the relayer address — enable impersonation or front-running",
        "category": "config",
    },
    "0x4b0ee02a": {
        "name": "getRelayer",
        "sig": "getRelayer()",
        "risk": "medium",
        "reason": "Exposes the relayer address",
        "category": "config",
    },
    "0x1c5fb211": {
        "name": "getValidator",
        "sig": "getValidator()",
        "risk": "medium",
        "reason": "Exposes validator address — useful for targeting",
        "category": "config",
    },
    "0xb7ab4db5": {
        "name": "validators",
        "sig": "validators()",
        "risk": "medium",
        "reason": "Exposes validator set addresses",
        "category": "config",
    },

    # ----- Role-based access control (AccessControl) -----------------------

    "0x91d14854": {
        "name": "hasRole",
        "sig": "hasRole(bytes32,address)",
        "risk": "low",
        "reason": "Role query — enables enumeration of privileged accounts",
        "category": "auth",
    },
    "0x248a9ca3": {
        "name": "getRoleAdmin",
        "sig": "getRoleAdmin(bytes32)",
        "risk": "low",
        "reason": "Role admin query — reveals governance structure",
        "category": "auth",
    },
    "0xa217fddf": {
        "name": "DEFAULT_ADMIN_ROLE",
        "sig": "DEFAULT_ADMIN_ROLE()",
        "risk": "low",
        "reason": "Standard access-control constant — reveals role hierarchy",
        "category": "auth",
    },
    "0xca15c873": {
        "name": "getRoleMemberCount",
        "sig": "getRoleMemberCount(bytes32)",
        "risk": "low",
        "reason": "Enables enumeration of role members",
        "category": "auth",
    },
    "0x9010d07c": {
        "name": "getRoleMember",
        "sig": "getRoleMember(bytes32,uint256)",
        "risk": "medium",
        "reason": "Direct role member enumeration — enumerates all privileged addresses",
        "category": "auth",
    },

    # ----- Timelock --------------------------------------------------------

    "0xf27a0c92": {
        "name": "getMinDelay",
        "sig": "getMinDelay()",
        "risk": "low",
        "reason": "Timelock minimum delay — reveals governance timing",
        "category": "timelock",
    },
    "0x36568abe": {
        "name": "renounceRole",
        "sig": "renounceRole(bytes32,address)",
        "risk": "low",
        "reason": "Role renouncement function",
        "category": "timelock",
    },

    # ----- EIP-2535 Diamond ------------------------------------------------

    "0x7a0ed627": {
        "name": "facets",
        "sig": "facets()",
        "risk": "low",
        "reason": "Diamond: exposes all facet addresses and selectors",
        "category": "diamond",
    },
    "0x52ef6b2c": {
        "name": "facetAddresses",
        "sig": "facetAddresses()",
        "risk": "low",
        "reason": "Diamond: exposes all facet implementation addresses",
        "category": "diamond",
    },
    "0xadfca15e": {
        "name": "facetFunctionSelectors",
        "sig": "facetFunctionSelectors(address)",
        "risk": "low",
        "reason": "Diamond: exposes selectors per facet",
        "category": "diamond",
    },
    "0xcdffacc6": {
        "name": "facetAddress",
        "sig": "facetAddress(bytes4)",
        "risk": "low",
        "reason": "Diamond: maps selector to facet address",
        "category": "diamond",
    },

    # ----- ERC-20 standard (low risk, included for completeness) -----------

    "0x06fdde03": {
        "name": "name",
        "sig": "name()",
        "risk": "low",
        "reason": "ERC-20 token name",
        "category": "erc_standard",
    },
    "0x95d89b41": {
        "name": "symbol",
        "sig": "symbol()",
        "risk": "low",
        "reason": "ERC-20 token symbol",
        "category": "erc_standard",
    },
    "0x313ce567": {
        "name": "decimals",
        "sig": "decimals()",
        "risk": "low",
        "reason": "ERC-20 token decimals",
        "category": "erc_standard",
    },
    "0x18160ddd": {
        "name": "totalSupply",
        "sig": "totalSupply()",
        "risk": "low",
        "reason": "ERC-20 total supply",
        "category": "erc_standard",
    },
    "0x70a08231": {
        "name": "balanceOf",
        "sig": "balanceOf(address)",
        "risk": "low",
        "reason": "ERC-20 balance query",
        "category": "erc_standard",
    },
    "0xdd62ed3e": {
        "name": "allowance",
        "sig": "allowance(address,address)",
        "risk": "low",
        "reason": "ERC-20 allowance query",
        "category": "erc_standard",
    },

    # ----- ERC-721 ---------------------------------------------------------

    "0xc87b56dd": {
        "name": "tokenURI",
        "sig": "tokenURI(uint256)",
        "risk": "low",
        "reason": "ERC-721 token URI",
        "category": "erc_standard",
    },
    "0x6c0360eb": {
        "name": "baseURI",
        "sig": "baseURI()",
        "risk": "low",
        "reason": "ERC-721 base URI — may reveal IPFS/storage backend",
        "category": "erc_standard",
    },
    "0xe8a3d485": {
        "name": "contractURI",
        "sig": "contractURI()",
        "risk": "low",
        "reason": "Contract metadata URI",
        "category": "erc_standard",
    },

    # ----- ERC-165 ---------------------------------------------------------

    "0x01ffc9a7": {
        "name": "supportsInterface",
        "sig": "supportsInterface(bytes4)",
        "risk": "low",
        "reason": "ERC-165 interface detection",
        "category": "erc_standard",
    },

    # ----- Pausable --------------------------------------------------------

    "0x5c975abb": {
        "name": "paused",
        "sig": "paused()",
        "risk": "low",
        "reason": "Reveals whether the contract is paused",
        "category": "config",
    },

    # ----- Initializable ---------------------------------------------------

    "0x8129fc1c": {
        "name": "initialize",
        "sig": "initialize()",
        "risk": "medium",
        "reason": "Initializer present — may be re-initializable or misconfigured",
        "category": "config",
    },
}


# ---------------------------------------------------------------------------
# Sensitive keyword lists used by heuristics (name-based matching)
# ---------------------------------------------------------------------------

HIGH_RISK_KEYWORDS = frozenset({
    "secret", "mnemonic", "seed", "privatekey", "private_key", "rootkey",
    "masterkey", "masterkey", "recoverykey", "backupkey", "hotkey",
    "signingkey", "encryptionkey", "decryptionkey",
})

MEDIUM_RISK_KEYWORDS = frozenset({
    "guardian", "signer", "signers", "recovery", "backup", "credential",
    "credentials", "auth", "authkey", "merkleroot", "whitelist", "allowlist",
    "blacklist", "blocklist", "relayer", "relayers", "validator", "validators",
    "admin", "superuser", "superadmin", "privileged", "privilegeduser",
    "multisig", "quorum", "threshold", "config", "configuration",
    "operator", "operators", "executor", "executors", "proposer", "proposers",
})

LOW_RISK_KEYWORDS = frozenset({
    "owner", "token", "treasury", "feerecipient", "protocol", "registry",
    "factory", "router", "manager", "controller", "governance",
    "pendingowner", "pendingadmin",
})

# Sensitive Solidity types (in output positions of view functions)
SENSITIVE_OUTPUT_TYPES = frozenset({
    "bytes", "bytes32", "bytes16", "bytes8", "bytes4", "string",
    "bytes[]", "bytes32[]",
})

# Keywords in type names that suggest sensitivity
SENSITIVE_TYPE_KEYWORDS = frozenset({
    "key", "secret", "seed", "mnemonic", "credential", "auth", "hash",
    "root", "proof", "sig", "signature", "recover",
})

# Debug-style function name prefixes/suffixes
DEBUG_KEYWORDS = frozenset({
    "debug", "_dump", "dump_", "getdump", "getstate", "getinternalstate",
    "internals", "_internal", "testonly", "test_only",
})


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def lookup_selector(selector: str) -> Optional[Dict]:
    """
    Return metadata for a known selector, or None.
    selector should be lowercase 0x-prefixed hex string.
    """
    return SELECTOR_DB.get(selector.lower())


def classify_name(name: str) -> Optional[Dict]:
    """
    Return a risk classification dict if *name* matches a sensitive keyword,
    otherwise None.
    The name is normalised to lowercase with underscores stripped for matching.
    """
    normalised = name.lower().replace("_", "").replace("-", "")

    for kw in HIGH_RISK_KEYWORDS:
        if kw in normalised:
            return {
                "risk": "high",
                "reason": f"Name contains sensitive keyword '{kw}'",
                "matched_keyword": kw,
            }

    for kw in MEDIUM_RISK_KEYWORDS:
        if kw in normalised:
            return {
                "risk": "medium",
                "reason": f"Name contains potentially sensitive keyword '{kw}'",
                "matched_keyword": kw,
            }

    for kw in DEBUG_KEYWORDS:
        if kw in normalised:
            return {
                "risk": "medium",
                "reason": f"Name suggests debug/internal access ('{kw}')",
                "matched_keyword": kw,
            }

    for kw in LOW_RISK_KEYWORDS:
        if kw in normalised:
            return {
                "risk": "low",
                "reason": f"Name contains operational keyword '{kw}'",
                "matched_keyword": kw,
            }

    return None


def classify_type(type_str: str) -> Optional[Dict]:
    """
    Return risk classification if the output type looks sensitive.
    type_str example: "bytes32", "bytes", "string", "address"
    """
    lower = type_str.lower().replace(" ", "")
    if lower in SENSITIVE_OUTPUT_TYPES:
        return {
            "risk": "medium",
            "reason": f"Output type '{type_str}' can carry arbitrary byte data",
        }
    for kw in SENSITIVE_TYPE_KEYWORDS:
        if kw in lower:
            return {
                "risk": "medium",
                "reason": f"Type name contains sensitive keyword '{kw}'",
            }
    return None
