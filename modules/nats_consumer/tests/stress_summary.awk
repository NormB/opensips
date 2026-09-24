# stress_summary.awk -- the stress_3way end-of-run report.
# Input: the samples CSV.  Vars: dur (run length, s), csv (path shown),
# warmup (s).  The RSS baseline is the first sample taken at least
# `warmup` seconds into the run: opensips faults in its shared-memory
# pages and fills its caches in the first minute, so growth measured from
# t=0 flags every healthy run.  A run with no sample that late falls back
# to the first sample.
    NR == 1 { next }
    NR == 2 { rss0 = $3; pulls0 = $4; deliv0 = $5; acks0 = $6; base_up = $2 }
    NR > 2 && !warm && $2 + 0 >= warmup + 0 { rss0 = $3; base_up = $2; warm = 1 }
    {
        if ($3 > rss_max) rss_max = $3
        rss_last = $3; pulls_last = $4; deliv_last = $5; acks_last = $6
        redeliv_last = $9; log_err_last = $12; log_warn_last = $13
        n++
    }
    END {
        rss_growth = (rss0 > 0) ? (rss_last - rss0) * 100.0 / rss0 : 0
        deliv_delta = deliv_last - deliv0
        ack_ratio = (deliv_delta > 0) ? (acks_last - acks0) * 1.0 / deliv_delta : 0
        status = (rss_growth > 50) ? "WARN_RSS_GROWTH" : "ok"
        printf "\n========================================\n"
        printf "  stress_3way summary\n"
        printf "  samples:                 %d\n", n
        printf "  duration:                %ds\n", dur
        printf "  rss kb (base->last):     %d -> %d (peak %d)\n", rss0, rss_last, rss_max
        printf "  rss baseline:            sample at %ds (warm-up %ds)\n", base_up, warmup
        printf "  rss growth:              %.2f%%\n", rss_growth
        printf "  pulls (delta):           %d\n", pulls_last - pulls0
        printf "  msgs_delivered (delta):  %d\n", deliv_delta
        printf "  acks (delta):            %d\n", acks_last - acks0
        printf "  ack/delivered ratio:     %.4f\n", ack_ratio
        printf "  redeliveries (last):     %d\n", redeliv_last
        printf "  log errors (last):       %d\n", log_err_last
        printf "  log warns (last):        %d\n", log_warn_last
        printf "  status:                  %s\n", status
        printf "  samples csv:             %s\n", csv
        printf "========================================\n"
    }
