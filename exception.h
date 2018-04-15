#ifndef EXCEPTION_H
#define EXCEPTION_H

class Exception
{
private:
	std::string reason;
public:
	Exception(std::string reason);
	std::string getReason();
};

#endif