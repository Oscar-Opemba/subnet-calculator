# Release checklist

Before publishing a release, a maintainer must run the full test suite and bytecode compilation, review CodeQL, Dependency Review, Dependabot, and OpenSSF Scorecard findings, confirm no secrets or generated caches are tracked, inspect dependency and action changes, and verify the documented threat boundary.

The maintainer should test the CLI help path, a valid example, representative malformed inputs, and the loopback web interface where present. Network-enabled checks must use synthetic fixtures or authorized public targets only. Release notes must identify behavior changes, security fixes, compatibility changes, and known limitations.

Do not publish a release that introduces unbounded I/O, redirect following, proxy inheritance, dynamic code execution, credential logging, public binding, or undocumented collection of submitted values.
