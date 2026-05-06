# 030 — UTF-8 / non-ASCII payload survives nats_publish round-trip.
case_begin "030_publish_payload_unicode"

sub_out="$WORKDIR/030_sub.out"
sub_pid=$(nats_sub_oneshot "test.sip.unicode" "$sub_out")
sleep 0.5

# Publish via the route with a Unicode payload by sending a MESSAGE
# whose body is UTF-8.  The route forwards $rb to NATS.
cat > "$WORKDIR/030.xml" <<'EOF'
<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<scenario name="MESSAGE-UTF8">
  <send retrans="500">
    <![CDATA[
      MESSAGE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: alice <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: bob <sip:bob@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 MESSAGE
      Max-Forwards: 70
      Content-Type: text/plain; charset=utf-8
      Content-Length: [len]

      hello-CAFE
    ]]>
  </send>
  <recv response="200" timeout="3000" />
</scenario>
EOF

# Re-bind sub to test.sip.message (that's where the route publishes).
kill "$sub_pid" 2>/dev/null
sub_pid=$(nats_sub_oneshot "test.sip.message" "$sub_out")
sleep 0.5

sipp_send "$WORKDIR/030.xml"
for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

if grep -q 'hello-CAFE' "$sub_out"; then
    check "Unicode-tagged ASCII payload round-trips" ok
else
    check "Unicode-tagged ASCII payload round-trips" fail \
        "$(head -3 "$sub_out")"
fi
