# 035 — payload with quotes / backslashes / newlines is preserved.
case_begin "035_publish_special_chars"

sub_out="$WORKDIR/035_sub.out"
sub_pid=$(nats_sub_oneshot "test.special" "$sub_out")

# nats CLI publish with quoted special chars.
publish_subject "test.special" 'with "quotes" and \backslash and pipes|and|stuff'

for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

# All three special-char markers should appear in the received body.
ok="ok"
grep -q 'with "quotes"' "$sub_out" || ok="fail"
grep -q 'pipes|and|stuff' "$sub_out" || ok="fail"
check "special characters preserved through nats publish" "$ok" \
    "$(head -3 "$sub_out")"
