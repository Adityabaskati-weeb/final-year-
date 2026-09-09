# Acceptance Status

Implemented: synthetic generator removal; Zeek-compatible feature contract; official labelled-log downloader with checksums; real-data training and independent capture splits; threshold selection on validation; recorded-data analysis; authenticated live collector ingestion; explicit capture controls; Windows Scapy/Npcap capture for the registered private lab device; labelled lab-session tooling; failed-model live gating.

Verified locally: 26 regression tests, Python compilation, frontend production build, real v2 training on nine official captures, backend health/status, recorded capture analysis without live records or blocks, read-only evidence export, the dashboard on port 8020, and live capture of real ESP32-to-laptop packets into stored flow rows.

Failed: untouched held-out evaluation detects 11/32 attacks (recall 34.375%), misses 21 and flags 933 benign rows (FPR 19.597%). The model is NOT ready for live protection. Historical exact-feature-filtered evaluation detected 0/20 attacks; it is retained as a secondary diagnostic. High aggregate accuracy reflects class imbalance.

Promoted lab scope: an independently captured ESP32 session set produced 108 normal and 50 controlled private-probe flows. The lab-specific model achieved 100% recall and 0% false-positive rate on the untouched test sessions and passed hash-linked promotion. This is a topology- and extractor-specific result, not general IoT protection.

Not verified/complete: generalization to independent devices/days, gateway enforcement, promoted attack-family attribution, probability calibration, and model-driven physical alarm verification. The explicit hardware alarm test is separate from model detection. The live binary model is extractor-gated and limited to the registered ESP32 lab topology.

Existing synthetic runtime artifacts are ignored rather than destructively deleting user data; the application no longer loads them. Old synthetic rows are hidden from current views. Expand and validate actual data before changing eligibility.
