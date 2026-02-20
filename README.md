# CKL_Comparator
Cybersecurity RMF STIG Comparison Tool

# CKL Comparison and Merge Tool

A PowerShell tool for comparing and merging DISA STIG CKL files while preserving historical audit data and maintaining audit continuity.

This tool allows auditors to safely carry forward findings, comments, and statuses between CKLs without losing information.

---

# Overview

This tool compares a newly generated CKL against a previously completed CKL and performs a structured merge.

It performs the following operations:

1. Matches vulnerabilities using `Vuln_Num`
2. Compares audit fields:
   - STATUS
   - FINDING_DETAILS
   - COMMENTS
3. Preserves historical audit data
4. Allows manual merge decisions
5. Prevents duplicate review comments
6. Supports resume capability

---

# Features

## Intelligent Comparison

- Matches vulnerabilities using unique identifiers
- Detects status changes
- Preserves audit history automatically
- Prevents accidental data overwrite

---

## Interactive Merge Control

When mismatches are detected, you can choose:

- `o` — Use OLD values
  - Copies:
    - STATUS
    - FINDING_DETAILS
    - COMMENTS
  - Adds review annotation if missing

- `n` — Keep NEW values
  - Leaves new audit data unchanged

- `m` — Manual override
  - Allows manual entry of:
    - STATUS
    - FINDING_DETAILS
    - COMMENTS

- `<` — Go to previous mismatch
- `>` — Go to next mismatch
- `x` — Exit and save

---

## Resume Capability

If a merge session is interrupted, the tool allows you to resume safely.

Resume mode:

- Loads previously merged CKL
- Continues merge progress
- Prevents duplicate entries

---

## Safe File Handling

The tool protects your original files:

- Original CKLs are never modified
- Creates new merged files automatically
- Supports overwrite or versioned merge files
- Uses UTF-8 encoding without BOM

---

# Required Directory Structure

- CKL-Comparison-Tool/
  - PreviouslyCompletedCKL/
    - previous.ckl
  - NewCKL/
    - new.ckl
  - MergeScript.ps1

---

# Output Files

The tool creates merged files such as:

- new_Merged.ckl
- new_Merged1.ckl
- new_Merged2.ckl

Resume mode reuses existing merged files.

---

# Example Workflow

Typical audit cycle:

1. Previous audit CKL exists
   - Contains prior findings and comments

2. New CKL generated from scan

3. Tool compares both files

4. Tool merges audit data

5. Output CKL contains:
   - Previous comments
   - Current comments
   - Review annotation

---

# Known Issues
 - Resume capability causes duplicate text (Current/Previous Finding/Comment). Fix currently in-progress. 
