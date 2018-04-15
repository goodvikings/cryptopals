#include <string>
#include "exception.h"

Exception::Exception(std::string reason)
{
	this->reason = reason;
}

std::string Exception::getReason()
{
	return reason;
}
