"""
TrustLens backend application package.

Modules:
    main: FastAPI application and HTTP endpoints.
    models: Pydantic request and response models.
    state: Encapsulated runtime state (rate limiting, caching, spend budget).
    errors: Shared error hierarchy.
    analyzer: Slither invocation and result normalization.
    fetcher: Verified-source retrieval from the block explorer.
    proxy: On-chain proxy resolution.
    payments: Payment and monthly-pass verification.
    rpc: Chain RPC client construction.
    ai: Model triage of scan results.
"""
