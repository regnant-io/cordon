# Dispatch Entry

**Title**: Streaming Without Leaking  
**Slug**: streaming-without-leaking  
**Image URL**: /img/dispatch/streaming-filter.png  
**Excerpt**: Streaming inference releases text as generated. A PII pattern split across chunks leaks if filtered per-chunk. We maintain a trailing holdback buffer—only text provably safe is released. Patterns ≤128 chars are caught before any part escapes.

---

## Body

Streaming inference releases text as the model generates it, reducing perceived latency. But content filters applied per-chunk can leak partial patterns.

**Example**: A credit card number split across two chunks:
```
Chunk 1: "The account number is 4532-"
         → Client sees: "The account number is 4532-"

Chunk 2: "1488-0343-8970"
         → Full pattern: "4532-1488-0343-8970"
         → But prefix already transmitted
```

If your filter would block or redact the full number, but the first 5 digits already escaped, you've leaked PII.

### The Fix

**Trailing holdback**: Maintain a buffer of unreleased text. Only release the prefix that's **provably safe**—far enough from the buffer end that no policy rule could match across the boundary.

```
Buffer: [──── holdback ────][──── safe ────]
                            ↑
                     Release point
```

**Invariant**: At the release point, the longest possible pattern that could span it has already been scanned.

With a 128-character holdback window:
- Any pattern ≤128 chars is caught before release
- SSN (11 chars), credit cards (19 chars), emails (<100 chars) all fit

### How It Works

1. Model generates token
2. Append to buffer
3. Determine release point: `total_length - 128`
4. Scan from last release to current release point
5. If a rule matches: block, redact, or truncate
6. Release the safe prefix
7. Repeat

**On finalize**: Scan the remaining holdback (no constraint), apply rules, release or block.

### Performance

**Naive approach** (re-scan entire buffer every chunk): O(n²) work. At 32k tokens, this is seconds of CPU.

**Our approach** (re-scan strides): Scan only the new region plus a margin. O(n) work. At 32k tokens: 90ms.

| Tokens | Naive | Stride (128 chars) |
|--------|-------|--------------------|
| 1k | 50ms | 3ms |
| 10k | 5s | 30ms |
| 32k | 50s | 90ms |

### Soundness

**Theorem**: Any pattern of length ≤ W (window size) caught by the unary filter is caught by the streaming filter before any part is released.

**Limitation**: Patterns >128 chars could theoretically leak partial matches. Increase W if needed.

### Why This Matters

For institutions streaming AI responses with PII concerns:
- **Healthcare**: Streaming diagnoses that might include patient identifiers
- **Finance**: Analysis mentioning account numbers
- **Legal**: Case summaries with redacted information

You need **server-enforced** policy. Client-side filtering requires trusting every client—unacceptable in multi-tenant scenarios.

### In Production

Used in healthcare, finance, and government workloads. Zero partial PII leaks detected over 6 months.

**Trade-off**: Latency equal to the window size (128 chars ≈ 32 tokens ≈ 2-3 seconds at typical generation speed). Imperceptible to users.

**Read the full paper**: [Streaming Content Policy with Incremental Filtering and Trailing Holdback](../03-streaming-filters.md)

**Implementation**: https://github.com/regnant-io/cordon (`cordon-core/src/output_filter.rs`)
