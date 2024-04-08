#include "tests.hpp"
#include "string"
using namespace std;

int main(int argv,char* args[]) {
    ::srand(time(NULL));
    //TEST_DNS_BYTES(t39);
    //TEST(txt);
    //test53(argv,args);
    testPacketToQuery();
    return 0;
}
