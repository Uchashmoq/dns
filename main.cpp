#include "tests/test1.hpp"
#include "string"
#include "tests/packetTest.h"
#include "tests/diffProblem.h"
using namespace std;

int main(int argv,char* args[]) {
    //srand(time(NULL));
    clientSendPackets(argv,args);
    //testQr();
    //TEST(E1154);
    //DIFF(test5,test5w);
    //testA();
   // echoServer();
  // simulateEchoServer();
    return 0;
}
