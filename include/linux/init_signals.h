static struct signal_with_aux_struct init_signals_aux = {
	.sig = INIT_SIGNALS(init_signals_aux.sig),
};

#define init_signals	init_signals_aux.sig
