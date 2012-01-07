#include "nfdnsbl_config.h"
#include "config.h"

int main()
{
	option_t option;
	init_option(&option);
	print_option(&option);
	read_config(&option,CONFFILE);
	print_option(&option);
	destroy_option(&option);
	return 0;
}

