## Summary

<!-- What does this change and why? -->

## Related issue

<!-- Closes #NNN, if any. -->

## Testing

<!-- How was this validated? Which Oracle tiers did you run against
     (tests/odbc/run-matrix.sh), and did the sanitizer build stay clean? -->

- [ ] Ran the relevant tests / integration matrix
- [ ] Built clean under the sanitizers (`build-asan`) where runtime paths changed

## Checklist

- [ ] **Clean-room**: no Oracle source, no decompiled binaries, no code copied
      from any other driver — public references and own packet captures only
      (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
- [ ] REUSE-compliant: new files carry SPDX copyright + license tags.
- [ ] Commits are signed off (`Signed-off-by:`).
