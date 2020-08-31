#include"header.h"
enum class Cpp11Enum  
{  
  RED = 10,  
  BLUE = 20  
};  
  
struct Wowza  
{  
  virtual ~Wowza() = default;  
  virtual void foo(int i = 0) = 0;  
};  
  
struct Badabang : Wowza  
{  
  void foo(int) override;  
  
  bool operator==(const Badabang& o) const;  
};  
  
template <typename T>  
void bar(T&& t);  

void say_hello(){
  float f=1.9f;
  int a=9-1;
  int b=-2;
  char * s =hello("world");
  char s2[]="i am here";
}
