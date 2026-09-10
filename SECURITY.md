# Security Policy

Dendrite is endpoint security software. Please report vulnerabilities privately so
they can be investigated before public disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for a suspected security vulnerability.**

Use GitHub's private vulnerability reporting / Security Advisory interface for this
repository:

```text
https://github.com/anthrosystems/dendrite/security/advisories/new
```

Include as much of the following as is safely available:

- affected commit, tag, or version;
- affected Dendrite component or crate;
- operating system and kernel version;
- reproduction steps or proof of concept;
- expected and actual security boundary;
- required attacker privileges or preconditions;
- potential impact;
- relevant logs with secrets and personal data removed;
- suggested mitigation, if known.

Please avoid submitting real credentials, private keys, personal telemetry, malware
samples containing third-party confidential data, or unrelated sensitive host data.

## Scope

Security-relevant areas include, but are not limited to:

- privileged action execution;
- authorisation and policy bypass;
- MAGI/quorum bypass;
- `dendrite-guard` trust or integrity bypass;
- IPC authentication or authorisation;
- TOCTOU vulnerabilities;
- quarantine escape or tampering;
- update/remediation verification;
- anti-downgrade controls;
- unsafe parsing of hostile telemetry or persisted data;
- Memory Graph corruption that can improperly grant authority;
- privilege escalation;
- arbitrary command or code execution;
- denial of service that defeats required security controls;
- exposure of sensitive telemetry or security state.

## Security architecture expectations

Dendrite is designed around several invariants:

```text
Detection -> Evidence -> Incident -> Action Proposal
          -> MAGI -> Quorum -> Policy -> Guard -> Executor
```

Detection and evidence are not authority.

Privileged action execution is intended to use the transaction:

```text
PROPOSAL -> PREPARE -> REVALIDATE -> COMMIT -> VERIFY
```

A compromise should be able to remove authority but must not create new authority.

Reports showing a violation of these invariants are particularly important.

## Supported versions

Dendrite is currently pre-release software and has not yet established a long-term
supported-version policy.

Until stable releases begin, security fixes will generally target the current
development branch and the most recent published pre-release where practical.

## Disclosure

Please allow time for investigation, remediation, testing, and release coordination
before publishing vulnerability details.

Once a fix is available, Anthrosystems may publish a GitHub Security Advisory with
technical details, affected versions, fixed versions, and mitigation guidance.

## Non-security bugs

Crashes, incorrect output, usability problems, and other issues without a security
impact should be reported through the normal GitHub issue tracker.
