#include <stdbool.h>
#include <arpa/inet.h>

#include <kore/kore.h>
#include <kore/http.h>

bool
is_request_from_localhost (struct http_request *req)
{
	//switch (req->owner->family)
	switch (req->owner->addrtype)
	{
		case AF_INET:
			if (req->owner->addr.ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
				return true;
			break;

		case AF_INET6:
			return false;
			break;
	}

	return false;
}

