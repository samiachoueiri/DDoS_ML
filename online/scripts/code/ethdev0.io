; Define pipeline input ports
port in 0 ethdev 0000:07:00.0 rxq 0 bsz 32
port in 1 ethdev 0000:08:00.0 rxq 0 bsz 32

; Define pipeline output ports
port out 0 ethdev 0000:07:00.0 txq 0 bsz 32
port out 1 ethdev 0000:08:00.0 txq 0 bsz 32

