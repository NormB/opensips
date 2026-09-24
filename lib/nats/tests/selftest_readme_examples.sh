#!/bin/bash
#
# selftest_readme_examples.sh -- contract of test_readme_examples.sh:
# known-good examples pass, known-bad ones fail, and the way a fragment
# is wrapped (globals, modparams, route blocks, bare statements) is right.
#
# Needs the same built tree as the test itself; exits 77 otherwise.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$HERE/test_readme_examples.sh"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
FAILS=0

run() {  # run <readme> -> output of the test, rc in $RC
    OUT=$(README_EXAMPLES_FILES="$1" bash "$T" 2>&1); RC=$?
}
expect() {  # expect <description> <want-rc> <grep-pattern>
    if [ "$RC" -eq 77 ]; then echo "SKIP: $OUT"; exit 77; fi
    if [ "$RC" -eq "$2" ] && printf '%s\n' "$OUT" | grep -qE -- "$3"; then
        echo "  ok: $1"
    else
        echo "  FAIL: $1 (rc=$RC)"; printf '%s\n' "$OUT" | sed 's/^/      /'
        FAILS=$((FAILS + 1))
    fi
}

# 1. good fragments of every shape pass
cat > "$W/good.md" <<'EOF'
```opensips title="modparam only"
...
modparam("event_nats", "nats_url", "nats://127.0.0.1:4222")
...
```

```opensips title="bare statements"
nats_publish("a.b", "$rm");
if (cache_fetch("nats", "k.$ci", $var(v)))
    xlog("got $var(v)\n");
```

```opensips title="core setting plus route blocks"
udp_workers = 4
startup_route {
    nats_consumer_bind("id=j;stream=S;durable=d;filter=$$JS.x.>");
}
timer_route[t, 5] {
    if (nats_fetch("j", 5)) { nats_ack(); }
}
```

```text
not checked
```
EOF
run "$W/good.md"
expect "good examples of every shape pass" 0 'OK \(3 examples\)'

# 2. each known-bad example is caught on its own
cat > "$W/bad.md" <<'EOF'
```opensips title="adjacent literals"
startup_route {
    nats_consumer_bind("id=j;" "stream=S;durable=d");
}
```

```opensips title="comparison on a function call"
if (nats_fetch("j") == 1) { nats_ack(); }
```

```opensips title="unknown function"
cache_query("nats", "domain", "example.com", $var(r));
```

```opensips title="unescaped dollar"
startup_route {
    nats_consumer_bind("id=j;stream=S;ephemeral=1;filter=$JS.x.>");
}
```

```opensips title="function not allowed in the route"
nats_consumer_bind("id=j;stream=S;durable=d");
```
EOF
run "$W/bad.md"
expect "all five bad examples fail" 1 '5 of 5 example\(s\) FAILED'

# 3. no examples at all is an error, not a pass
printf '# nothing here\n' > "$W/none.md"
run "$W/none.md"
expect "a README with no examples is an error" 1 'no examples found'

if [ "$FAILS" -eq 0 ]; then echo "selftest_readme_examples: OK"; exit 0; fi
echo "selftest_readme_examples: $FAILS FAILED"; exit 1
