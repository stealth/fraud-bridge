#ifndef __base64_h__
#define __base64_h__

#include <string>

std::string &b64_encode(const std::string&, std::string&);

std::string &b64_decode(const std::string&, std::string&);

#endif

