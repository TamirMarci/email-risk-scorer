# Issue 2 — Fix Sender/Link Domain Mismatch

## Problem
Mismatch rule is too noisy.

## Requirements
- Compare root domains only
- Ignore mismatch for:
  - public email providers
  - SaaS/ATS tools
  - recruiting context
- Treat tracking domains as neutral
- Apply only if both domains are not allowlisted

## Goal
Make mismatch a weak supporting signal only.
