# pwn
## 计算机内存和C语言的联系
### 例题
>给定一个ip地址（10进制）将其以标准的ip地址形式输出,输入不会超过4,294,967,295
即将输入案例转化为16进制后分成四组，其中每一组按照10进制输出 如下

3232236298 -> 0x C0 A8 03 0A->192  168  3 10
>输入案例：
3232236298

>输出案例：
192.168.3.10

优雅做法如下
```c
#include <stdio.h>
int main()
{
    int n;
    scanf("%d", &n);
    void *p = &n;
    unsigned char *rp = (unsigned char *)p;
    for (int i = 3; i >= 0; i--)
    {
        printf("%u", *(rp + i));
        if (i != 0){
            printf(".");
        }
    }
}
```

## 小端序
详见PPT

| 0a | 04 | A8 | C0 |
|----|----|----|----|

在计算机中，数据是采用bytes为单位进行存储的，即0x12在计算机中存储为0x12 不会改变，为了便于截取数据低位，采用**小端序**。对于一个数据0x12345678 ，它的存储结果就是 

**↓**

| 78 | 56 | 34 | 12 | 
|----|----|----|----|

此时如果我们想要其最低位 78 ，只需将此处指针以char形式访存即可得到。而如果采用大端序
     
| 12 | 34 | 56 | 78 | 
|----|----|----|----|

我们知道了78的地址，如若想要访问78，则可以输出，但是想要输出12345678，就要倒着去访问，非常麻烦，所以采用小端序。

可以看出，在将bytes以单位进行访存的结构下，小端序是更为方便的。
## integer bug
### sign detect
在pwn题中，这是最基础的一种漏洞，但是也是**最容易被忽略**的一种洞（尤其是后面栈溢出打习惯了，第一反应就是找溢出点）。例题如下
```c
#include<stdio.h>
void get_shell(){
    system("/bin/sh");
}
int main(){
    int n;
    scanf("%d",&n);
    if(n>=10){
        exit(0);
    }else{
        if(unsigned(n)>=100){
            puts("welcome to my shell");
            get_shell();
        }
    }
}
```
这个比较简单，输入一个较大的负数就可以拿shell
### integer overflow
在pwn题中，整数溢出可能会发生在绕过某些检验等地方，例题如下
```C
#include<stdio.h>
#include<stdlib.h>
void backdoor(){
    system("/bin/sh");
}
int main(){
    int n;
    char res=0;
    for(int i = 0; i < 2;i++){
        scanf("%d",&n);
        if ( n >= 10 ) {
            return 0;
        } else {
            res+=n;
        }
    }
    if(res == 100){
        puts("welcome to my shell");
        backdoor();
    }
}
```
这个题目的点在于，会将小于10的数加到res上，但是又要要求res等于100，此时这里的打法就是可以通过整数溢出。
char 是1个byte也就是8位

|1|1|0|0|1|0|0|0|
|-|-|-|-|-|-|-|-|

这个数是 -56

|1|0|0|1|1|1|0|0|
|-|-|-|-|-|-|-|-|

这个数是 -100

这两个数相加的结果是

|0|1|1|0|0|1|0|0|
|-|-|-|-|-|-|-|-|

也就是100，达到要求,拿到shell

## string bug
我们在c语言中学习过，c语言中字符串长度是没有限制的，字符串的结束是以 ascii码为0的字符表示的，即"\x00",所以没有\x00时，计算机在读不到"\x00"时会一直读下去，导致泄露一些东西
例题如下
```c
#include<stdio.h>
#include<random>
#include<unistd.h>
#include<stdlib.h>
void init(){
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}
void get_shell(){
    system("/bin/sh");
}
int main(){
    init();
    char a[4] ;
    int b;
    b=rand();
    puts("plz input a");
    read(0,a,10);
    puts(a);
    puts("you can guess what b is , if you are correct , I will give you a shell");
    scanf("%d",&guess);
    if(guess==b){
        puts("welcome_to_my_shell");
        get_shell();
    }
}
```
