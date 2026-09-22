; Define input ports for the second pipeline (from physical ports)
port in 0 ring RING0 bsz 1                  ; Input port for the second pipeline (from the first pipeline's output)

; Define output ports for the second pipeline (to physical ports)
port out 0 ethdev 0000:07:00.0 txq 0 bsz 1   ; First physical output port
port out 1 ethdev 0000:08:00.0 txq 0 bsz 1   ; Second physical output port

; port out 0 ethdev net_tap0 txq 0 bsz 1  ; First virtual output port
; port out 1 ethdev net_tap1 txq 0 bsz 1  ; Second virtual output port

