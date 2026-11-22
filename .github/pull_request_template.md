## Summary

<!-- What changes, and why. One or two sentences. -->

## Type of change

- [ ] Core code (`crates/`)
- [ ] Proofs or checks (Kani, hax, Miri, fuzzing, constant-time)
- [ ] Tests
- [ ] Tooling or CI
- [ ] Documentation only

## AI use

See [AI_POLICY.md](https://github.com/mosgird/protocols/blob/main/AI_POLICY.md) in mosgird/protocols. Answer every question. The boxes can be ticked by clicking them after the pull request is opened.

- Tool used (or "none"):
- Extent (tick every one that applies):
  - [ ] none
  - [ ] brainstorming
  - [ ] drafted text
  - [ ] generated code
  - [ ] review only
- AI-generated assets (art, icons, sound, music, fonts, video, 3D models, or any image or audio, including placeholders). Required; AI-generated assets are permanently prohibited:
  - [ ] none
- Cryptographic or key-handling content touched?
  - [ ] no
  - [ ] yes, human-written or line-by-line reviewed
- [ ] I can explain and defend every line in this pull request.
- [ ] If AI use is disclosed: every commit has `Co-authored-by` and `Task` trailers, and no session links appear in commits or here.

## Specification

<!-- The mosgird/protocols version or commit this change follows, and the sections it implements. For example: overview.md section 5.1, decision 0005. If the change needs a specification change, link the protocols pull request; it is merged first. -->

## Security and privacy impact

<!-- Required. State what this change adds or removes in terms of what contacts, group members, network observers, or transport relays can learn, and what it stores on the device. If there is no impact, say why. -->

## Checklist

- [ ] Tests that apply pass locally
- [ ] `unsafe` is only in `crates/mosgird-core/src/secure_mem.rs` (`sh scripts/check_unsafe.sh`)
- [ ] Secret material is held in `Secret` or `LockedBox`, compared only in constant time, and never logged
- [ ] Code that handles secrets is covered by the constant-time check (`tools/ct-check`)
- [ ] Behavior matches the specification; any difference is a protocols pull request, not a change here
- [ ] No uncertain statement is presented as fact
- [ ] No session links in commits or in this description
