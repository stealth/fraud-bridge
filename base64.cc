#include <string>
#include <cstring>
#include <limits>


namespace fraudbridge {


// Orig b64 encoding:
//static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";

using namespace std;

/* The base64 routines have been taken from the Samba 3 source (GPL)
 * and have been C++-ified
 */
string &b64_decode(const string &src, string &dst)
{
	unsigned int bit_offset = 0, byte_offset = 0, idx = 0, i = 0, n = 0, j = 0;
	const char *p = NULL;

	dst = "";
	string::size_type srclen = src.size();
	if (srclen >= numeric_limits<unsigned int>::max() - 10)
		return dst;
	dst.reserve(srclen + 10);
	dst.resize(srclen + 10);
	while (j < srclen && (p = strchr(b64, src[j]))) {
		idx = (int)(p - b64);
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		dst[byte_offset] &= ~((1<<(8-bit_offset))-1);
		if (bit_offset < 3) {
			dst[byte_offset] |= (idx << (2-bit_offset));
			n = byte_offset+1;
		} else {
			dst[byte_offset] |= (idx >> (bit_offset-2));
			dst[byte_offset+1] = 0;
			dst[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
			n = byte_offset+2;
		}
		j++; i++;
	}

	// in original B64, this would be '='
	if (src[j] == '-' && n > 0)
		--n;

	dst.resize(n);
	return dst;
}


string &b64_encode(const string &src, string &dst)
{
	unsigned int bits = 0;
	int char_count = 0, i = 0;

	dst = "";
	string::size_type len = src.size();
	while (len--) {
		unsigned int c = (unsigned char)src[i++];
		bits += c;
		char_count++;
		if (char_count == 3) {
			dst += b64[bits >> 18];
			dst += b64[(bits >> 12) & 0x3f];
			dst += b64[(bits >> 6) & 0x3f];
	    		dst += b64[bits & 0x3f];
		    	bits = 0;
		    	char_count = 0;
		} else	{
	    		bits <<= 8;
		}
    	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		dst += b64[bits >> 18];
		dst += b64[(bits >> 12) & 0x3f];
		if (char_count == 1) {
			dst += '-';	// '='
			dst += '-';	// '='
		} else {
			dst += b64[(bits >> 6) & 0x3f];
			dst += '-';	// '='
		}
	}
	return dst;
}

}

#if 0
#include <iostream>

int main()
{
	string s1, s2;
	s1 = "Afdsfdsf894378rhgufdhgzdsfhgfhdsfgsf89ds7f8ds8";
	cout<<s1<<endl;
	cout<<b64_encode(s1, s2)<<endl;
	cout<<b64_decode(s2, s1)<<endl;
	return 0;
}

}

#endif



