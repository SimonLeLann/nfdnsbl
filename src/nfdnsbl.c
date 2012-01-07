#include "nfdnsbl_config.h"
#include "config.h"
#include <stdlib.h>

option_t option;

void exit_callback(void)
{
	destroy_option(&option);
}

int main()
{
	init_option(&option);
	atexit(exit_callback);
	read_config(&option,CONFFILE);
	print_option(&option);

	return 0;
}

