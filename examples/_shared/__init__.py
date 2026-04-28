"""Shared helpers for the framework quickstart demos.

This package is imported by examples/{langchain,autogen,langgraph}-quickstart/
demo.py at runtime. It carries the framework-agnostic plumbing — provider
selection, SPIFFE identity fetch, Biscuit issuance, governed-session
setup, receipt-chain verification, and end-of-session attestation — so
each per-framework demo only contains the framework-specific glue.

No specific LLM model identifiers live in this package; provider config
is sourced from environment variables at runtime (see
``demo_scenes._require_model_env``).
"""
