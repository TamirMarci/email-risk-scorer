# Issue 1 — Refactor Brand Impersonation Logic

## Problem
Current logic is too aggressive and causes false positives.

## Requirements
- Split into severity levels:
  - CRITICAL: typo-squatting + sensitive request
  - HIGH: brand mismatch without trust signals
  - MEDIUM/LOW: brand appears but SaaS/recruiter context
- Do NOT treat brand mention alone as critical

## Goal
Reduce false positives for legitimate company emails.
