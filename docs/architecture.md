# Architecture

WebShield separates policy parsing, fragment rendering, bundle verification and local activation. Policies are parsed into validated models; renderers never consume raw TOML values. Activation accepts only a code-owned Debian/systemd profile with fixed destinations and command tuples.

```text
TOML policy -> validation -> fragments + manifest -> verified bundle -> local administrator helper
```

The helper is not reachable through HTTP and does not accept arbitrary commands, units or paths.
