# Dispatch Entry

**Title**: Audit Logs You Can Verify Offline  
**Slug**: audit-logs-offline-verification  
**Image URL**: /img/dispatch/audit-chain.png  
**Excerpt**: Traditional audit logs are signed by the operator you're auditing. If they have root access, they can rewrite entries undetectably. We built a system where verification keys derive from your master key—offline verification, no network call, tamper-evident.

---

## Body

Traditional audit logs have a trust problem: they're signed by the same operator you're auditing. If that operator has root access to the logging server, they can rewrite an entry, recompute the signature, and present a falsified history that verifies perfectly.

For institutions running AI on infrastructure they don't fully control—governments on cloud providers, central banks on third-party infrastructure, hospitals processing patient data—this is unacceptable.

### The Fix

We've built an audit system where the verification key comes from **your** master key, not the operator's.

**Hash chain**: Each audit entry commits to the previous entry via SHA-256. Modifying entry 5 breaks the chain at entry 6.

**Client-derived signing key**: The log is signed with a key (K_log) derived from a Client Master Key that **you** hold, not the operator. You independently derive the verification key (K_log_pub) and check the entire chain offline—no network call, no asking the operator for anything.

**Result**: An operator with root access can delete the log entirely, but they cannot rewrite a single entry without you detecting it. The signature breaks, and you know something's wrong.

### Why This Matters

When you audit AI inference:
- You're asking "Did someone query about classified material?"
- You're asking "Who authorized this expensive workload?"
- You're asking "Was this decision properly logged?"

If the operator can silently remove the evidence, the audit is theater. With client-derived verification keys, tampering leaves cryptographic proof.

### The Catch

This works perfectly **if** you hold the Client Master Key in an HSM the operator cannot access. If the operator has the CMK (current implementation), they can re-sign entries—but only before you anchor the chain head with a third party.

**Anchoring**: Every N minutes, record the current chain head (sequence number, hash, timestamp) with an independent witness—a timestamping service, a notary, even a tweet. Any rewrite before that anchor is now detectable by comparing the recorded anchor to the current chain.

### Performance

- **Append entry**: <1ms (write + fsync)
- **Verify 1M entries**: 30 seconds (single-threaded, commodity hardware)
- **Storage**: ~500 bytes per entry (~500 MB per million entries)

### In Production

We've run this for 6+ months on production workloads. Zero detected chain breaks. Verification is linear time, offline, and requires zero operator cooperation.

**Read the full paper**: [Operator-Independent Audit Verification Through Client-Derived Keys](../01-operator-independent-audit.md)

**Implementation**: https://github.com/regnant-io/cordon (`cordon-audit` crate, `cordon-verify-log` tool)
