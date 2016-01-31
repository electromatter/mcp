#include "utils.h"
#include "stubs.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	char hex[1024];
	unsigned char digest[20];
	mcp_sha1(digest, "BitOfAByte", 5);
	mcp_hexdigest(hex, digest, sizeof(digest));
	printf("%s\n", hex);
	return 0;
}
