#include "buffer.h"

char buffer_2_space[BUFFER_ERRSIZE];
static buffer it = BUFFER_INIT(buffer_unixwrite, 2, buffer_2_space, sizeof buffer_2_space);
buffer *buffer_2 = &it;
