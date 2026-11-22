# Security policy

This repository holds the Mosgird core library, which both apps are built on. It will hold users' private keys, encrypt and decrypt their messages, and protect local storage. A flaw here affects every app. Problems here are high priority: a bug that exposes keys, plaintext, or the contents of local storage matters most, and so does a timing or memory side channel on secret data.

## Reporting a vulnerability

Do not report security problems in a public issue or pull request.

Report them privately with GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. You can also go directly to https://github.com/mosgird/core/security/advisories/new.

Include:

- what the problem is, and where it is (file, function, or commit);
- which platform and build it affects;
- what an attacker could do with it, including whether keys, message content, identities, or metadata are exposed;
- steps to reproduce, or a proof of concept if you have one;
- whether you want to be credited.

We read every report. We do not yet guarantee a response time, and this page will say so if that changes.

## Scope

In scope: anything in this library that lets someone other than the user read messages, obtain private keys, forge identities, bypass end-to-end encryption, or learn metadata the protocol says is hidden. The protocol's requirements are in [mosgird/protocols](https://github.com/mosgird/protocols); code here that breaks them is in scope even when the protocol document itself is correct. This includes code that reveals more to contacts, group members, network observers, or transport relays than the specification's overview section 3.3 lists. An example is leaking a network address that the chosen transport is meant to hide.

Also in scope: secret-dependent timing or memory access, secrets left in memory after use, and `unsafe` code that is unsound.

Out of scope: problems in third-party libraries, unless our use of them is at fault; reports that need access to accounts or devices you do not own; denial-of-service testing against infrastructure you do not own.

## Disclosure

We ask for coordinated disclosure: report first, give us a reasonable time to fix the problem, and do not publish details until a fix is released or we agree on a date. We credit reporters who want credit.

## Supported versions

No version is released yet. Only `main` is supported. When releases exist, this section lists which ones receive security fixes.
