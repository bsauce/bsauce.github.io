---
layout: post
title: Linux 安全缓解机制总结
categories: [Kernel-exploit]
description: Linux 安全缓解机制总结
keywords: Kernel, Exploit, Defense
---

# Linux 安全缓解机制总结

### 学习资料：

- [linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

- [A Decade of Linux Kernel Vulnerabilities, their Mitigation and Open Problems-2017](https://github.com/maxking/linux-vulnerabilities-10-years)

- [The State of Kernel Self Protection-2018](https://outflux.net/slides/2018/lca/kspp.pdf)
- [PaX/Grsecurity 代码分析——各种安全机制](https://github.com/hardenedlinux/grsecurity-101-tutorials/tree/master/grsec-code-analysis)
- [Linux每个版本对应的安全更新](https://outflux.net/blog/)
- [linux安全机制的论文](https://github.com/akshithg/linux-security-papers)



**防护研究团队**：

SELinux (NSA)、AppArmor (OpenSuSE/Ubuntu)、PaX / grsecurity (Spender)、各手机厂商、独立研究（论文）。

---

## 1.简介

#### （1）SELinux

介绍：由美国NSA维护。基于强制访问控制MAC（**Mandatory Access Control**）实现，基于角色的访问控制——进程只能访问那些在他的任务中所需要文件，简化用户的权限管理，减少系统开销。由NSA编写并设计成内核模块包含到内核中，相应的某些安全相关的应用也被打了SELinux的补丁。

Linux缺点：对于以上这些的不足，[防火墙](https://baike.baidu.com/item/防火墙)，[入侵检测系统](https://baike.baidu.com/item/入侵检测系统)都是无能为力的。而SELinux则能大幅强化访问权限。

- **存在特权用户root**：任何人只要得到[root](https://baike.baidu.com/item/root)的权限，对于整个系统都可以为所欲为。
- **对于文件的访问权的划分不够细**：在[linux系统](https://baike.baidu.com/item/linux系统)里，对于文件的操作，只有「[所有者](https://baike.baidu.com/item/所有者)」，「所有组」，「其他」这3类的划分。对于「其他」这一类里的用户再细细的划分的话就没有办法了。
- **SUID程序的权限升级**：如果设置了SUID权限的程序有了漏洞的话，很容易被攻击者所利用。
- **DAC(Discretionary Access Control）问题**：[文件目录](https://baike.baidu.com/item/文件目录)的所有者可以对文件进行所有的操作，这给系统整体的管理带来不便。

SELinux优点：它通过对于用户，进程权限的最小化，即使受到攻击，进程或者用户权限被夺去，也不会对整个系统造成重大影响。

- **对访问的控制彻底化**（MAC）：对于所有的文件，目录，端口这类的资源的访问，都可以是基于策略设定的，这些策略是由管理员定制的、一般用户是没有权限更改的。

- **对于进程只赋予最小的权限** （Type Enforcement）：Te概念在 SELinux里非常的重要。它的特点是对所有的文件都赋予一个叫type的文件类型标签，对于所有的进程也赋予各自的一个叫 domain的 标签。Domain标签能够执行的操作也是由access vector在策略里定好的。

- **防止权限升级**（domain迁移 ）：在用户环境里运行点对点[下载软件](https://baike.baidu.com/item/下载软件)azureus，你当前的domain是fu_t，但是，你考虑到安全问题，你打算让他在azureus_t里运行，你要是在terminal里用命令启动azureus的话，它的进程的domain就会默认继承你实行的shell的fu_t。

  有了domain迁移的话，我们就可以让azureus在我们指定的azureus_t里运行，在安全上面，这种做法更可取，它不会影响到你的fu_t。

- **对于用户只赋予最小的权限**（RBAC—role base access control) ：对于用户来说，被划分成一些ROLE，即使是ROOT用户，你要是不在sysadm_r里，也还是不能实行sysadm_t管理操作的。因为，那些ROLE可以执行那些domain也是在策略里设定的。ROLE也是可以迁移的，但是也只能按策略规定的迁移。



#### （2）AppArmor——基于MAC实现

介绍：由OpenSuSE/Ubuntu维护。跟SELinux一样，使用 [Linux Security Modules](https://en.wikipedia.org/wiki/Linux_Security_Modules) (LSM) 实现。是SELinux的一个备选，SELinux是对文件加标签，AppArmor是对文件路径，配置起来AppArmor更简单，且AppArmor对系统的修改更少。

#### （3）PaX/grsecurity——采用patch的形式

介绍：开始由老一代黑客Pax维护，后由grsecurity团队维护。采用patch形式加入到linux。

---

## 2. 历史

#### （1）什么是Grsecurity/PaX？

[PaX](http://pax.grsecurity.net/)是针对linux kernel的一个加固版本的补丁，它让linux内核的内存页受限于最小权限原则，是这个星球上有史以来最优秀的防御系统级别0day的方案，第1版的设计和实现诞生于2000年，那可是一个没有 ASLR/RELRO/NX/CANARY/FORITY/PIE都没有的年代，这些今天意义上的现代 mitigation技术不管是linux/windows/macosx都多少抄袭和模仿了PaX的设计和实 现，但有很多朋友会问：既然这东东这么厉害，为什么不在linux mainline里？ PaX没有进入Linux内核upstream的原因不止一个，甚至有时候都不是纯粹技术本身的问题：

1) [PaX Team并不在意PaX是否进入Linux主干代码](http://unix.stackexchange.com/questions/59020/why-are-the-grsecurity-patches-not-included-in-the-vanilla-kernel)，但多年来有很多关心Linux内核安全的人不断的尝试把PaX的代码分拆成小的patch提交给Linux内核社区。

2) Linux内核社区认为PaX的代码难以维护，而Linux内核社区更喜欢花时间在性能和新功能上，而非安全。

3) Linux内核社区和Linux基金会受到由各个大厂商的影响，大厂商对于安全的要求取决于他们的客户的需求，如果很多真相不曝光大厂商是不会在意安全性的

4) 商业公司在意他们的主要利润来源，比如Five-eyes国家（美国，英国，加拿大，澳大利亚和新西兰）的政府项目都会统一采购SELinux的项目，所以大厂商都会花费精力去满足这一需求，这也是SELinux虽然备受争议但是一直有厂商和NSA持续投入的原因。

SELinux也是一个著名的开源MAC（强制访问控制）实现，是由NSA(美国国家安全局）于1990年代末发起的项目，于2000年以GPL自由软件许可证开放源代码，2003年[合并到Linux内核中](http://www.internetnews.com/ent-news/article.php/3317331)，过去10年中关于[是否NSA在其中放后门的争论](https://www.schneier.com/blog/archives/2008/04/nsas_linux.html)没有停过，一些人认为应该信任SELinux，因为它是以GPL自由软件许可证公开的源代码，也有人认为它是NSA参与过的项目，所以不应该信任。2013年Snowden曝光棱镜后更多的人极度的不信任NSA，认为[NSA有对Android代码植入后门的前科](http://www.zerohedge.com/news/2013-07-09/nsa-has-inserted-its-code-android-os-bugging-three-quarters-all-smartphones)，所以应该[怀疑所有NSA积极参与的项目包括SELinux](http://www.eteknix.com/nsa-has-code-running-in-the-linux-kernel-and-android/)。目前MAC的开源实现里，SELinux主要由RedHat/CentOS/Fedora社区维护，Apparmor主要由OpenSuSE/Ubuntu社区维护，关于SELinux是否应该使用是一个长久争论的话题，个人认为这取决于你的威胁建模，如果你是Five-Eyes阵营你当然应该使用SELinux，如果你是其他阵营比如德国或者中国，或许你应该考虑其他选择。

针对Linux内核的MAC实现都是基于LSM( Linux Security Module)去实现的，LSM利用了一堆CAPABILITY的 机制提供了一些限制用户态程序访问控制的接口，SELinux和Apparmor都是基于LSM开发的，注意LSM并不是一个传统意义上的linux kernel module，至少在2个地方不同于普通module:

1) 必须在bootloader启动内核时启动，不能在内核加载完后启动。

2) 不能同时启动2个LSM的实现。

但PaX Team是一群old school security hackers，他们认为LSM一方面打破了 “security as a whole”的哲学，另外一方面对于[内核漏洞没有防御能力](https://grsecurity.net/compare.php)，虽然在早年Linux内核社区以及大厂商不管是刻意还是无意的想要掩盖这一点，但[时间](https://grsecurity.net/spender_summit.pdf)证明PaX Team是正确的。其 实当人们谈到Gnu/Linux安全性比windows/OSX更好时，其实未必，至少linux内核社区并没有把安全性放在首位，Linus Torvalds从来都不是太care安全问题，不是吗？

PaX从一开始就主要关注如何防御和检测memory corruption，PaX由PaX team维护，Grsecurity主要包括了RBAC（基于角色的访问控制）和一系列对PaX的改进（包括抗爆破，ASLR的抗信息泄漏，不允许文件系统级别的任意代码执行等），Grsecurity主要由Spender维护，最近几年这2组Patch都合并到了一起发布，所以我们都称这组补丁为Grsecurity/PaX或者PaX/Grsecurity。

Grsecurity包括了很多简单的自动化特性，比如RBAC系统可以通过学习模式（你可以选择基于进程/用户或者整个系统）来自动化创建规则，这些规则都是人类可读的纯文本格式（Shawn：SELinux是使用难以审计的二进制的格式），报错信息有助于根据攻击类型来制定相应的规则。

#### （2）对比

SELinux：最强大但最复杂的

AppArmor：比SELinux更简单的配置/管理

grsecurity：由于自动培训的简单配置，比访问控制更多的功能

| Feature                             | SELinux                                                      | AppArmor                                            | grsecurity                     |
| ----------------------------------- | ------------------------------------------------------------ | --------------------------------------------------- | ------------------------------ |
| Automated                           | No (audit2allow and system-config-selinux)                   | Yes (Yast wizard)                                   | Yes (auto traning / gradm)     |
| Powerful policy setup               | Yes (very complex)                                           | Yes                                                 | Yes                            |
| Default and recommended integration | CentOS / RedHat / Debian                                     | Suse / OpenSuse                                     | Any Linux distribution         |
| Training and vendor support         | Yes (Redhat)                                                 | Yes (Novell)                                        | No (community forum and lists) |
| Recommend for                       | Advanced user                                                | New / advanced user                                 | New users                      |
| Feature                             | Pathname based system does not require labelling or relabelling filesystem | Attaches labels to all files, processes and objects | ACLs                           |

#### （3）KSPP（Kernel Self Protection Project）

KSPP目标：由于很多保护机制已经存在很久了，如PaX/grsecurity和一些论文，KSPP目标就是将这些保护机制整合到linux本身，实现内核自保护。

PaX/Grsecurity的test patch于2017年4月26日[关闭公开下载](https://grsecurity.net/passing_the_baton.php)。Linux基金会是导致商业用户，个人用户和社区用户失去访问test patch的权利的罪魁祸首。原因如下：

- [基础架构联盟](https://www.coreinfrastructure.org/)是由19家大厂商赞助190万美金每年，由Linux基金会管理的组织。[KSPP一开始是由基础架构联盟资助](https://lwn.net/Articles/663361/)，[KSPP](https://www.coreinfrastructure.org/grants)一直在尝试[移植和实现PaX/Grsecurity](https://hardenedlinux.github.io/system-security/2016/12/13/kernel_mitigation_checklist.html)的一些功能到主线内核，一开始的动机和起点都是不错的。但是KSPP所完成的防御性功能完全无法和PaX/Grsecurity相提并论，比如他们移植防御机制的同时也引入了bug（能被利用？）或者由于Linux内核社区政治的原因导致了防御机制不完整实现。更糟糕的是Linux基金会[不断的市场PR](https://forums.grsecurity.net/viewtopic.php?f=7&t=4476)让更多的大众误认为他们是”Neo”。这些市场PR盗窃了PaX/Grsecurity的名声。据我们所知，非常遗憾，目前为止没有一位KSPP的维护者站出来向公众揭露真相，曾经有一名h4rdenedzer0成员[尝试与LF/CII建立对话](https://lwn.net/Articles/703000/)但没有结果。
- 从0到1的创造力是稀有资源，而PaX/Grsecurity作为操作系统防御的起源即使到今天也是最有效的防御方案。如果你是x86的GNU/Linux用户，自从2001年以来你或多或少的收益于PaX/Grsecurity。你的机器有一些PaX/Grsecurity产物，从SEGEXEC/PAGEEXEC到NX/DEP，从PaX ASLR到Linux主线内核包括OSX和Windows的ASLR，从KERNEXEC/UDEREF到SMEP/SMAP( armv7/arm64的PXN/PAN)等等。多年以来PaX/Grsecurity一直领先业界。更重要的是PaX team和Spender慷慨的在过去16年中把他们的工作成功分享给了自由软件世界。一些真正的安全专家过去几天发表的评论都在赞叹PaX/Grsecurity的强大（看看twitter和一些GNU/Linux发行版的邮件列表），不幸的是，这正是信息安全行业的现状：只有少数人知道真相。如果人们幻想KSPP可以成为另外一个可选防御方案，那PaX/Grsecurity的商业支持者可能会停止资金上的支持。这是我们所不愿意看到的。
- 关闭公开下载并不意味着PaX/Grsecurity变成了非自由软件。那些购买订阅的用户依然可以访问源代码。我们没有看到任何有违反GPL的地方。总之，这是PaX team和Spender的作品，他们有权做任何的决定。我们明白为什么他们这么做。当像Linux基金会持续从PaX/Grsecurity盗取名声和大厂商（WinRiver/Intel）从PaX/Grsecurity某些特性上赚钱但从来没有任何贡献这种事情发生时，没人会比PaX team和Spender更痛苦。
- KSPP逐渐成为PaX/Grsecurity的负担。
- 来自最近Spender访谈的引用：“当涉及自由软件时，太多的评论家和抱怨者，太少的能花费大半生时间专注于原创的工作。当这些原创的工作被大公司抄袭并且用于误导性的市场宣传，只会越来越少的人愿意持续工作和分享。所以我们重新专注于那些尊重我们时间的人。”。自由软件世界持续的失去像[Jonathan Zdziarski](https://www.zdziarski.com/blog/?p=6296), PaX team和Spender这样真正的黑客。这个世界之所以邪恶并不是因为有太多坏人，而是因为太多被我们称为“好人”的群体的不作为。

#### （4）Now

PaX的思路的确非常的震撼，那 都是10多年前的设计和实现，在这个一天云计算一天雾计算的年代，虽然关注本 质的黑客越来越少，但地下精神并未死去，PaX Team就是一个活生生的例证，相 反，不少old school黑客都坚信其实old school的数量并没有减少，至少我个人 相信这是真的…Phrack没死，Grsecurity/PaX没死，DNFWAH也没死，希望更多的 黑客分享自己的hacking之旅。

Phrack is not dead, Grsecurity/PaX is not dead, DNFWAH is not dead, The Underground spirit is not dead…..If they were, that’d be on us!

=——————————————————————–=

To one of the most respected old school communities: Grsecurity/PaX. We/I salute you!!!

---

## 3.防御机制

#### （1）Linux Kernel Defence Map

![linux-kernel-defence-map](\images\posts\Linux-defense\linux-kernel-defence-map.svg)

说明：

- 绿——Linux mainline defense，加入到内核主流的防御机制

- 白——通用防御机制

- 蓝——Out-of-tree defense

- 紫——漏洞检测

- 灰——商用防御

- 粉——漏洞

- 浅蓝——HW 华为防御？

- 黄——漏洞利用技术

防御机制：

- [RANDSTRUCT](https://lwn.net/Articles/722293/)：The `randstruct` plugin is a new GCC add-on that lets the compiler randomize the layout of C structures. The `randstruct` plugin randomly rearranges fields at compile time given a randomization seed. When potential attackers do not know the layout of a structure, it becomes much harder for them to overwrite specific fields in those structures.

- [LATENT_ENTROPY](https://lwn.net/Articles/688492/)：This plugin mitigates the problem of the kernel having too little entropy during and after boot for generating crypto keys. This plugin mixes random values into the latent_entropy global variable in functions marked by the __latent_entropy attribute. The value of this global variable is added to the kernel entropy pool to increase the entropy.

- [PAX_RANDKSTACK](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/PAX_RANDKSTACK.md)：由 PaX Team 实现的 PAX_RANDKSTACK，是针对进程内核栈的随机化。由于内核栈本身的实现，内核中是可以任意访问没有任何防护的。随机化对栈布局的打乱，配合内核栈信息的擦除，能够有效防止内核信息泄漏，不容易猜透内存的布局。

- [__ro_after_init](https://linux.cn/article-7411-1.html)：函数指针和敏感变量必须不可写，对于那些在 `__init` 时初始化的变量可以标记为（新的和正在开发的）`__ro_after_init`属性。

- [PAX_REFCOUNT](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/PAX_REFCOUNT.md)：针对引用计数溢出的加固。内核对象引用计数不断增加，当发生溢出时，引用计数为 0，内存即可被释放，而此时程序还有对该指针所值内存的引用，就有可能发生 use-after-free,可以用做攻击利用。实现包括两个部分，一部分是探测引用计数的溢出，一部分是溢出发生时的异常处理。[REFCOUNT_FULL](https://lwn.net/Articles/728626/)：This implements refcount_t overflow protection on x86 without a noticeable performance impact, though without the fuller checking of REFCOUNT_FULL. This is done by duplicating the existing atomic_t refcount implementation but with normally a single instruction added to detect if the refcount has gone negative (e.g. wrapped past INT_MAX or below zero). When detected, the handler saturates the refcount_t to INT_MIN / 2. With this overflow protection, the erroneous reference release that would follow a wrap back to zero is blocked from happening, avoiding the class of refcount-overflow use-after-free vulnerabilities entirely.

- [TIF_FSCHECK flag](https://patchwork.kernel.org/patch/10398269/)：Check address limit on user-mode return") added a mechanism to check the addr_limit value before returning to userspace. Any call to set_fs() sets a thread flag, TIF_FSCHECK, and if we see that on the return to userspace we go out of line to check that the addr_limit value is not elevated.

- [bpf_jit_harden](https://www.kernel.org/doc/Documentation/sysctl/net.txt)：When BPF JIT compiler is enabled, then compiled images are unknown addresses to the kernel, meaning they neither show up in traces nor in /proc/kallsyms. This enables export of these addresses, which can be used for debugging/tracing. If bpf_jit_harden is enabled, this feature is disabled. [GRKERNSEC_JIT_HARDEN](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options)：If you say Y here, the native code generated by the kernel's Berkeley Packet Filter (BPF) JIT engine will be hardened against JIT-spraying attacks that attempt to fit attacker-beneficial instructions in 32bit immediate fields of JIT-generated native instructions.  The attacker will generally aim to cause an unintended instruction sequence of JIT-generated native code to execute by jumping into the middle of a generated instruction.  This feature effectively randomizes the 32bit immediate constants present in the generated code to thwart such attacks.
  
- [CONFIG_MODULE_SIG](https://cateee.net/lkddb/web-lkddb/MODULE_SIG.html)：Check modules for valid signatures upon load: the signature is simply appended to the module.

- [SECURITY_LOADPIN](https://lwn.net/Articles/682302/)：Security-conscious developers have long worried about code that is loaded into the kernel at run time; such code could clearly, if malicious, subvert the security of the entire system. That is the policy that LoadPin was created to implement. It takes advantage of the relatively new [kernel file-loading mechanism](https://lwn.net/Articles/676101/) to intercept all attempts to load a file into the kernel; these include loading kernel modules, reading firmware, loading a security policy, or loading an image for `kexec()`.

- [CONFIG_LDISC_AUTOLOAD](https://cateee.net/lkddb/web-lkddb/LDISC_AUTOLOAD.html)：Historically the kernel has always automatically loaded any line discipline that is in a kernel module when a user asks for it to be loaded with the TIOCSETD ioctl, or through other means. This is not always the best thing to do on systems where you know you will not be using some of the more "ancient" line disciplines, so prevent the kernel from doing this unless the request is coming from a process with the CAP_SYS_MODULE permissions.

  Say 'Y' here if you trust your userspace users to do the right thing, or if you have only provided the line disciplines that you know you will be using, or if you wish to continue to use the traditional method of on-demand loading of these modules by any user.

- [request_module_cap](https://lwn.net/Articles/740461/)：And the thing is, the patch series seems to already introduce largely the better model of just making it site-specific. Introducing that request_module_cap() thing and then using it for networking is a good step. IOW, extend on that request_module_cap() model, and introduce (perhaps) a "request_module_dev()" call that basically means "the user opened the device node for the requested module".

- [GRKERNSEC_MODHARDEN](https://xorl.wordpress.com/2010/11/08/grsecuritys-grkernsec_modharden-protection-and-the-rds-local-root-exploit/)：Of course, the main reason that ‘[linux-rds-exploit.c](http://www.vsecurity.com/download/tools/linux-rds-exploit.c)‘ doesn’t work against grsecurity kernels is PAX_UDEREF as the post comments but ‘GRKERNSEC_MODHARDEN’ will prevent a widely used exploitation technique that was arrived along with auto-loading modules. As in this case, it is common to trigger an operation such as creating a socket in order to force the kernel into auto-loading the required to module. Since RDS is usually compiled as a module and it’s rarely used that’s what was happening in Dan Rosenberg’s exploit. The kernel was auto-loading the vulnerable module and then it was a common exploitation procedure.

- [CONFIG_STRICT_KERNEL_RWX](https://cateee.net/lkddb/web-lkddb/STRICT_KERNEL_RWX.html)：If this is set, kernel text and rodata memory will be made read-only, and non-text memory will be made non-executable. This provides protection against certain security exploits (e.g. executing the heap or modifying text)

  These features are considered standard security practice these days. You should say Y here in almost all cases.

- [CONFIG_DEBUG_WX](https://cateee.net/lkddb/web-lkddb/DEBUG_WX.html)：Generate a warning if any W+X mappings are found at boot. This is useful for discovering cases where the kernel is leaving W+X mappings after applying NX, as such mappings are a security risk.

- [ARM: RODATA_FULL_DEFAULT_ENABLED](https://lore.kernel.org/linux-arm-kernel/20200306173217.44372-1-steven.price@arm.com/)：This requires the linear region to be mapped down to pages, which may adversely affect performance in some cases.

- [PAX_PAGEEXEC](https://hardenedlinux.github.io/system-security/2015/05/25/pageexec-old.html)：讨论在IA-32处理器上实现不可执行（比如用户态代码所在的页只有读和 写的权限，但没有执行的权限）。因为处理器的原生页表和页目录不提供这样的 功能，所以这个实现有一定的难度。

- [PAX_KERNEXEC](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/PAX_KERNEXEC.md)：PAX_KERNEXEC 是 PaX 针对内核的 No-execute 实现，可以说是内核空间版的 pageexec/mprotect。由于 PAGEEXEC 的实现已经完成了一部分工作（实际上内核的内存访问同样也是透过 page-fault 去处理），KERNEXEC 代码主要包括这几方面：

  - 对内核空间的内存属性进行设置（RO & NX）
  - 内核态的内存访问的控制
  - 可加载内核模块（W^X）和 bios/efi 内存属性的控制
  - 透过 gcc-plugin 的配合实现

- [XPFO-eXclusive Page Frame Ownership](https://lwn.net/Articles/700606/)：This patch series adds support for XPFO which protects against 'ret2dir' kernel attacks. The basic idea is to enforce exclusive ownership of page frames by either the kernel or userspace, unless explicitly requested by the kernel. Whenever a page destined for userspace is allocated, it is unmapped from physmap (the kernel's page table). When such a page is reclaimed from userspace, it is mapped back to physmap. Additional fields in the page_ext struct are used for XPFO housekeeping.
  Specifically two flags to distinguish user vs. kernel pages and to tag unmapped pages and a reference counter to balance kmap/kunmap operations and a lock to serialize access to the XPFO fields. [Add support for eXclusive Page Frame Ownership (XPFO)](https://lwn.net/Articles/700647/)

- [SMEP/PXN](https://hardenedlinux.github.io/system-security/2016/05/23/kernel_self_protection.html)：内核必须永远不能执行用户空间的内存。内核也必须永远不能在没有显式预期的情况下访问用户空间内存。这些规则可以被基于硬件的限制（x86的SMEP/SMAP，ARM的PXN/PAN）或者通过模拟（ARM的内存域）。这种方式阻断了执行和数据不能传递到被控制的用户空间内存里，只能强制攻击在内核内存中进行。

- [PAX-RAP-Reuse Attack Protector](https://lwn.net/Articles/713808/)：By saying Y here the kernel will check indirect control transfers in order to detect and prevent attacks that try to hijack control flow by overwriting code pointers. Note that the implementation requires a gcc with plugin support, i.e., gcc 4.5 or newer.  You may need to install the supporting headers explicitly in addition to the normal gcc package.

  The grsecurity developers have [announced](https://www.grsecurity.net/rap_announce_full.php) the first release of the "Reuse Attack Protector" (RAP) patch set, aimed at preventing return-oriented programming and other attacks. "RAP is our patent-pending and best-in-breed defense mechanism against code reuse attacks. It is the result of years of research and development into Control Flow Integrity (CFI) technologies by PaX. The version of RAP present in the test patch released to the public today under the GPLv2 is now feature-complete."

- [Clang CFI](https://clang.llvm.org/docs/ControlFlowIntegrity.html)：Clang includes an implementation of a number of control flow integrity (CFI) schemes, which are designed to abort the program upon detecting certain forms of undefined behavior that can potentially allow attackers to subvert the program’s control flow. These schemes have been optimized for performance, allowing developers to enable them in release builds. [ControlFlowIntegrityDesign](https://clang.llvm.org/docs/ControlFlowIntegrityDesign.html)

- [SMAP/PAN](https://lwn.net/Articles/517475/)：SMAP(Supervisor Mode Access Prevention，管理模式访问保护)和SMEP(Supervisor Mode Execution Prevention，管理模式执行保护)的作用分别是禁止内核访问用户空间的数据和禁止内核执行用户空间的代码。arm里面叫 PXN(Privilege Execute Never) 和PAN(Privileged Access Never)。

- [PAX_MEMORY_UDEREF](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/PAX_MEMORY_UDEREF.md)：PAX_MEMORY_UDEREF 是针对 Linux 的内核/用户空间分离的重要特性，连同 KERNEXEC 构成了强悍的地址空间划分隔离，防御了大量针对内核的漏洞利用，比如 ret2usr/ret2dir 这类将特权级执行流引向用户空间的攻击方式，即便是陆续被硬件实现的 SMEP/SMAP( x86) 或者 PXN/PAN( ARMv7/ARMv8.1) 亦难与 UDEREF 比肩。在 32-bit 的 x86 下，分离的特性很大部分是透过分段机制的寄存器去实现的，而 amd64 以后由于段寄存器功能的削弱，PaX 针对 64-bit 精心设计了 KERNEXEC/UDEREF，包括使用 PCID 特性和 per-cpu-pgd 的实现等。UDEREF诞生于ret2usr攻击已经在地下大规模使用的年代，虽然2004年PaX/Grsecurity公布了i386版本的KERNEXEC，但并未对数据访问严格限制，所以在一定程度上也方便了ret2usr和任意写的漏洞利用，随后PaX/Grsecurity为了弥补这一风险于2007年公布了i386版本的UDEREF，之后又实现了x64以及armv7的UDEREF，在众多UDEREF实现中安全性和性能最好的是[i386](https://grsecurity.net/~spender/uderef.txt)和[armv7](https://forums.grsecurity.net/viewtopic.php?f=7&t=3292&sid=d67decb18f1c9751e8b3c3de3d551075)，在x64的进化之路则显得更坎坷，2010年x64的版本很弱，且无法防御多层deref后的情况，之后在2013年的实现中被称为强实现的版本极大的增强防护的同时也利用Sandybridge+开始后的硬件特性PCID提升性能，后续UDEREF的改进(2017版)主要是利用硬件特性SMAP提升了性能的同时保证安全性，这篇分析是基于2013版的实现进行的。

  UDEREF的实现主要包括几个方面：

  - per-cpu-pgd 的实现，将内核/用户空间的页目录彻底分离，彼此无法跨界访问
  - PCID 特性的使用，跨界访问的时候产生硬件检查
  - 内核/用户空间切换时，将用户空间映射为不可执行以及一些刷新 TLB 配合实现

- 

  

- [mmap_min_addr](https://wiki.debian.org/mmap_min_addr)：`mmap_min_addr` is a kernel tunable that specifies the minimum virtual address that a process is allowed to mmap. Allowing processes to map low values increases the security implications of a class of defects known as "kernel NULL pointer dereference" defects. If a malicious local user finds a way to trigger one of these NULL pointer defects, they can exploit it to cause system hangs, crashes, or otherwise make parts of the system unusable. If this user is also able to map low portions of virtual memory, they can often further exploit this issue to gain increased privileges.

  The downside to preventing applications from mmap'ing low virtual memory addresses is that certain applications depend on this functionality. dosemu, qemu and wine are three such applications that exist in Debian. See the [application specific information](https://wiki.debian.org/mmap_min_addr#apps) below.

- [PAGE_TABLE_ISOLATION](https://lwn.net/Articles/741878/)：**内核页表隔离**（Kernel page-table isolation，缩写KPTI，也简称PTI，旧称KAISER）是[Linux内核](https://baike.baidu.com/item/Linux内核)中的一种[强化](https://baike.baidu.com/item/强化)技术，旨在更好地隔离[用户空间](https://baike.baidu.com/item/用户空间)与内核空间的[内存](https://baike.baidu.com/item/内存)来提高安全性，缓解现代[x86](https://baike.baidu.com/item/x86) [CPU](https://baike.baidu.com/item/CPU)中的“[熔毁](https://baike.baidu.com/item/熔毁)”硬件安全缺陷。 [百度百科-内核页表隔离]([https://baike.baidu.com/item/%E5%86%85%E6%A0%B8%E9%A1%B5%E8%A1%A8%E9%9A%94%E7%A6%BB](https://baike.baidu.com/item/内核页表隔离))   [A page-table isolation update](https://lwn.net/Articles/752621/)

- [X86: MICROCODE](https://zhuanlan.zhihu.com/p/86432216)：我们现在普遍使用的电脑X86 CPU，采用的是复杂指令集（CISC)，指令很多，而且长短不一。如果所有的指令全部采用硬件解码，那将是一个不可能完成的任务。所以一条机器指令，将被拆解成数个类似RISC的精简微操作：微码，Micro-Ops，Microcode。而这些Micro-Ops，则可以完全被硬件执行。Eg， `pop [ebx]`   ->  `load temp, [esp]; store [ebx], temp; add esp, 4;` 。

  既然一条指令会被解码成microcode/Micro-Ops，如果转换后的microcode出了问题，打个补丁就行了呗。

- [spec_store_bypass_disable](https://www.suse.com/support/kb/doc/?id=000019189)：The mitigating solution is to disable the "Memory Disambiguation" feature in the processor, either system-wide or selectively for single processes.

  On Intel x86 systems, updated CPU microcode is required to enable this mitigation. This microcode is either supplied by your hardware / BIOS vendor or by SUSE using the official Intel released microcode packages.

  Note :The minimum required Intel microcode base-level for this mitigation is the Intel 20180807 release (across all versions of SLES).
  Mitigations need to be implemented for the Linux Kernel and for Hypervisors, both for passing through new CPU flags and MSR registers (on x86) and supporting of switching off/on the mitigation.

  For the Linux kernel, on both bare metal and virtual machines, it can be enabled / disabled using the kernel boot command line and/or with a thread-specific prctl() system call.

- [CONFIG_SLAB_FREELIST_RANDOM](https://www.openwall.com/lists/kernel-hardening/2016/04/27/6)：Provides an optional config (CONFIG_SLAB_FREELIST_RANDOM) to randomize the SLAB freelist. The list is randomized during initialization of a new set of pages. The order on different freelist sizes is pre-computed at boot for performance. Each kmem_cache has its own randomized freelist. Before pre-computed lists are available freelists are generated dynamically. This security feature reduces the predictability of the kernel SLAB allocator against heap overflows rendering attacks much less stable.

- [CONFIG_SHUFFLE_PAGE_ALLOCATOR](https://cateee.net/lkddb/web-lkddb/SHUFFLE_PAGE_ALLOCATOR.html)：Randomization of the page allocator improves the average utilization of a direct-mapped memory-side-cache. See section 5.2.27 Heterogeneous Memory Attribute Table (HMAT) in the ACPI 6.2a specification for an example of how a platform advertises the presence of a memory-side-cache. There are also incidental security benefits as it reduces the predictability of page allocations to compliment SLAB_FREELIST_RANDOM, but the default granularity of shuffling on the "MAX_ORDER - 1" i.e, 10th order of pages is selected based on cache utilization benefits on x86.

  While the randomization improves cache utilization it may negatively impact workloads on platforms without a cache. For this reason, by default, the randomization is enabled only after runtime detection of a direct-mapped memory-side-cache. Otherwise, the randomization may be force enabled with the 'page_alloc.shuffle' kernel command line parameter.

- [slab_nomerge](https://www.openwall.com/lists/kernel-hardening/2017/06/20/48)：Some hardened environments want to build kernels with slab_nomerge already set (so that they do not depend on remembering to set the kernel command line option). This is desired to reduce the risk of kernel heap overflows being able to overwrite objects from merged caches, increasing the difficulty of these attacks. By keeping caches unmerged, these kinds of exploits can usually only damage objects in the same cache (though the risk to metadata exploitation is unchanged).

- [unprivileged_userfaultfd](https://lwn.net/Articles/782745/)：This patchset introduces a new sysctl flag to allow the admin to forbid users from using userfaultfd:

    $ cat /proc/sys/vm/unprivileged_userfaultfd
    [disabled] enabled kvm

  This new flag can add one more layer of security to reduce the attack surface of the kernel by abusing userfaultfd.  Here we grant the thread userfaultfd permission by checking against CAP_SYS_PTRACE capability.  By default, the value is "disabled" which is the most strict policy.  Distributions can have their own perferred value.

  The "kvm" entry is a bit special here only to make sure that existing users like QEMU/KVM won't break by this newly introduced flag.  What we need to do is simply set the "unprivileged_userfaultfd" flag to "kvm" here to automatically grant userfaultfd permission for processes like QEMU/KVM without extra code to tweak these flags in the admin code.

- [CONFIG_DEBUG_LIST](https://cateee.net/lkddb/web-lkddb/DEBUG_LIST.html)：Enable this to turn on extended checks in the linked-list walking routines. [CONFIG_DEBUG_SG](https://cateee.net/lkddb/web-lkddb/DEBUG_SG.html)：Enable this to turn on checks on scatter-gather tables. This can help find problems with drivers that do not properly initialize their sg tables. [CONFIG_DEBUG_CREDENTIALS](https://cateee.net/lkddb/web-lkddb/DEBUG_CREDENTIALS.html)：Enable this to turn on some debug checking for credential management. The additional code keeps track of the number of pointers from task_structs to any given cred struct, and checks to see that this number never exceeds the usage count of the cred struct. Furthermore, if SELinux is enabled, this also checks that the security pointer in the cred struct is never seen to be invalid. [CONFIG_DEBUG_NOTIFIERS](https://cateee.net/lkddb/web-lkddb/DEBUG_NOTIFIERS.html)：Enable this to turn on sanity checking for notifier call chains. This is most useful for kernel developers to make sure that modules properly unregister themselves from notifier chains. This is a relatively cheap check but if you care about maximum performance, say N. [CONFIG_DEBUG_VIRTUAL](https://cateee.net/lkddb/web-lkddb/DEBUG_VIRTUAL.html)：Enable some costly sanity checks in virtual to page code. This can catch mistakes with virt_to_page() and friends.

- [CONFIG_BUG_ON_DATA_CORRUPTION](https://cateee.net/lkddb/web-lkddb/BUG_ON_DATA_CORRUPTION.html)：Select this option if the kernel should BUG when it encounters data corruption in kernel memory structures when they get checked for validity.

- [PROTECTABLE_MEMORY](http://kernsec.org/pipermail/linux-security-module-archive/2018-February/005237.html)

- [STATIC_USERMODEHELPER](https://patchwork.kernel.org/patch/9519063/)：Some usermode helper applications are defined at kernel build time, while others can be changed at runtime.  To provide a sane way to filter these, add a new kernel option "STATIC_USERMODEHELPER".  This option routes all call_usermodehelper() calls through this binary, no matter what the caller wishes to have called.

  The new binary (by default set to /sbin/usermode-helper, but can be changed through the STATIC_USERMODEHELPER_PATH option) can properly filter the requested programs to be run by the kernel by looking at the first argument that is passed to it.  All other options should then be passed onto the proper program if so desired.

  To disable all call_usermodehelper() calls by the kernel, set STATIC_USERMODEHELPER_PATH to an empty string.

- [LKRG-Linux Kernel Runtime Guard](https://lwn.net/Articles/749707/)：LKRG performs runtime integrity checking of the Linux kernel and detection of security vulnerability exploits against the kernel. 

  While updating kernels frequently is generally considered a security best practice, there are many installations that are unable to do so for a variety of reasons. That means running with some number of known vulnerabilities (along with an unknown number of unknown vulnerabilities, of course), so some way to detect and stop exploits for those flaws may be desired. That is exactly what the [Linux Kernel Runtime Guard](http://www.openwall.com/lkrg/) (LKRG) is meant to do.

- [LOCKDOWN_LSM](https://lwn.net/Articles/791863/)：Technologies like UEFI secure boot are intended to guarantee that a locked-down system is running the software intended by its owner (for a definition of "owner" as "whoever holds the signing key recognized by the firmware"). That guarantee is hard to uphold, though, if a program run on the system in question is able to modify the running kernel somehow. Thus, proponents of secure-boot technologies have been trying for years to provide the ability to lock down many types of kernel functionality on secure systems. The latest attempt posted by Matthew Garrett, at an eyebrow-raising [version 34](https://lwn.net/ml/linux-kernel/20190622000358.19895-1-matthewgarrett@google.com/), tries to address previous concerns by putting lockdown under the control of a Linux security module (LSM).

- [STACKPROTECTOR](https://cateee.net/lkddb/web-lkddb/STACKPROTECTOR.html)：CONFIG_STACKPROTECTOR——This option turns on the "stack-protector" GCC feature. This feature puts, at the beginning of functions, a canary value on the stack just before the return address, and validates the value just before actually returning. Stack based buffer overflows (that need to overwrite this return address) now also overwrite the canary, which gets detected and the attack is then neutralized via a kernel panic.

  [gcc栈溢出保护机制：stack-protector](https://www.cnblogs.com/arnoldlu/p/11630979.html)

  - stack-protector：保护函数中通过alloca()分配缓存以及存在大于8字节的缓存。缺点是保护能力有限。
  - stack-protector-all：保护所有函数的栈。缺点是增加很多额外栈空间，增加程序体积。
  - stack-protector-strong：在stack-protector基础上，增加本地数组、指向本地帧栈地址空间保护。
  - stack-protector-explicit：在stack-protector基础上，增加程序中显式属性"stack_protect"空间。

- [FORTIFY_SOURCE](https://blog.csdn.net/whuzm08/article/details/96868157)：检查的函数：memcpy, mempcpy, memmove, memset, strcpy, stpcpy, strncpy, strcat, strncat, sprintf, vsprintf, snprintf, vsnprintf, gets。目的是检查dest变量内存是否溢出。[Security Technologies: FORTIFY_SOURCE](https://access.redhat.com/blogs/766093/posts/3606481)

- [slub_debug](https://www.cnblogs.com/arnoldlu/p/8568090.html)：slub_debug和kasan有一定的重复，部分slub_debug问题需要借助slabinfo去发现；kasan更快，所有问题独立上报，缺点是需要高版本GCC支持(gcc 4.9.2 or gcc 5.0)。slub_debug提供了内存检测小功能。kasan可以检测到越界访问、访问已释放内存、重复释放等类型错误，其中重复释放可以被slub_debug识别。对于非ARM64/x86平台，只能使用slub_debug进行内存问题分析；kasan更高效，但也需要更高的内核和GCC版本支持。

  [SLUB DEBUG原理](http://www.wowotech.net/memory_management/427.html)  [如何诊断SLUB问题](http://linuxperf.com/?p=184)

- [PAX_USERCOPY](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/PAX_USERCOPY.md)：在内核中 copy_from_user 和 copy_to_user 这组函数承担了数据在内核空间和用户空间之间拷贝的任务。PAX_USERCOPY 则在这组函数中实现了缓冲区的长度检查，当长度检查发现有溢出的可能时，就不会执行数据的复制，防止非法拷贝覆盖内存，破坏栈帧或堆。[HARDENED_USERCOPY](https://lwn.net/Articles/695991/) 原理类似。

- [GRKERNSEC_KSTACKOVERFLOW](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/KSTACKOVERFLOW.md)：Grsecurity 的 KSTACKOVERFLOW 特性是针对进程内核栈溢出的一些加固措施（一个是基于 Pax 的实现将 thread_info 分离出去，另一个是栈空间虚拟映射，提高安全性），主要包括：

  - 进程内核栈初始化时的vmap 与 thread_info 的分离
  - double_fault 中 Guard page 的检测
  - 一些指针的检查
  - 一些配合性的初始化

  [THREAD_INFO_IN_TASK](https://cateee.net/lkddb/web-lkddb/THREAD_INFO_IN_TASK.html)：将栈上的`thread_info`放入`task_struct`。Select this to move thread_info off the stack into task_struct. To make this work, an arch will need to remove all thread_info fields except flags and fix any runtime bugs.

  One subtle change that will be needed is to use try_get_task_stack() and put_task_stack() in save_thread_stack_tsk() and get_wchan().

  [VMAP_STACK](https://blog.csdn.net/rikeyone/article/details/105971720)：采用vmalloc申请的内存作为内核栈，这样内核栈可以利用vmalloc现成的guard page机制来检测"栈溢出"，但同时，其对应的物理内存也将不再保证是连续的，减少了内存碎片化。[Virtually mapped kernel stacks](https://lwn.net/Articles/692208/)

- [SCHED_STACK_END_CHECK](https://cateee.net/lkddb/web-lkddb/SCHED_STACK_END_CHECK.html)：This option checks for a stack overrun on calls to schedule(). If the stack end location is found to be over written always panic as the content of the corrupted region can no longer be trusted. This is to ensure no erroneous behaviour occurs which could result in data corruption or a sporadic crash at a later stage once the region is examined. The runtime overhead introduced is minimal.

- [PAX_MEMORY_STACKLEAK](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/MEMORY_LEAK.md)：关于内存信息泄漏。PAX_MEMORY_STACKLEAK 是一个依赖 gcc-plugin 针对进程内核栈的溢出和泄漏做加固的安全特性。这个特性的实现分为两部分，一是实现了 pax_erase_kstack 在进出内核空间时对进程内核栈的数据进行擦除，另一部分是借助 gcc-plugin，实现两个函数 pax_check_alloca 和 pax_track_stack 检查是否发生进程內核栈的溢出。[STACKLEAK](https://a13xp0p0v.github.io/2018/11/04/stackleak.html)：STACKLEAK is a Linux kernel security feature initially developed by Grsecurity/PaX. I have introduced STACKLEAK into the Linux kernel mainline. This article describes the inner workings of this security feature and why the vanilla kernel needs it. [Trying to get STACKLEAK into the kernel](https://lwn.net/Articles/764325/)

- Use-After-Free：[init_on_free/ init_on_alloc](https://lwn.net/Articles/791380/)：These are aimed at preventing possible information leaks and making the control-flow bugs that depend on uninitialized values more deterministic.

  Enabling either of the options guarantees that the memory returned by the page allocator and SL[AU]B is initialized with zeroes. SLOB allocator isn't supported at the moment, as its emulation of kmem caches complicates handling of SLAB_TYPESAFE_BY_RCU caches correctly.

  Enabling init_on_free also guarantees that pages and heap objects are initialized right after they're freed, so it won't be possible to access stale data by using a dangling pointer.

  [PAGE_POISONING](https://lwn.net/Articles/753261/)

  [PAX_MEMORY_SANITIZE](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/grsec-code-analysis/MEMORY_LEAK.md)：关于内存信息泄漏。PAX_MEMORY_SANITIZE 是一个用于将已被释放的内存，进行全面的擦除的特性。这个实现十分简单但是也十分有用，能够有效的抵御 “use after free” 类的攻击以及减少一些 infoleak。
  PAX_MEMORY_SANITIZE 的实现非常简单，slab 分配的流程是先申请 kmem_cache 再分配 slab，kmem_cache往往在初始化中做。真正实现擦除数据的工作只是在 slab 的释放中去做即可，但是还有一些琐碎的维护一些标志的工作。
  首先，PaX 通过 pax_sanitize_slab_setup 函数，在内核接收的 cmdline 里检测关于 pax_sanitize_slab 的设置，这里维护的标志供后面分配cache时读取（ pax_sanitize_slab_flags）来决定 sanitize 的模式。这部分代码比较简单，不做展开。

- [X86: X86_INTEL_UMIP](https://cateee.net/lkddb/web-lkddb/X86_INTEL_UMIP.html)：The User Mode Instruction Prevention (UMIP) is a security feature in newer Intel processors. If enabled, a general protection fault is issued if the SGDT, SLDT, SIDT, SMSW or STR instructions are executed in user mode. These instructions unnecessarily expose information about the hardware state.

  The vast majority of applications do not use these instructions. For the very few that do, software emulation is provided in specific cases in protected and virtual-8086 modes. Emulated results are dummy.

  [ARM: HARDEN_EL2_VECTORS](https://cateee.net/lkddb/web-lkddb/HARDEN_EL2_VECTORS.html)：Speculation attacks against some high-performance processors can be used to leak privileged information such as the vector base register, resulting in a potential defeat of the EL2 layout randomization.

  This config option will map the vectors to a fixed location, independent of the EL2 code mapping, so that revealing VBAR_EL2 to an attacker does not give away any extra information. This only gets enabled on affected CPUs.

- [kptr_restrict](https://lwn.net/Articles/420403/)：kptr_restrict 向用户空间内核中的指针(/proc/kallsyms-modules显示value全部为0)。[kptr_restrict 中文介绍](https://blog.csdn.net/gatieme/article/details/78311841)。

- [GRKERNSEC_HIDESYM](https://xorl.wordpress.com/2010/11/20/grkernsec_hidesym-hide-kernel-symbols/)：  If you say Y here, getting information on loaded modules, and displaying all kernel symbols through a syscall will be restricted to users with CAP_SYS_MODULE. For software compatibility reasons, `/proc/kallsyms` will be restricted to the root user. The RBAC system dcan hide that entry even from root. This option also prevents leaking of kernel addresses through several /proc entries.

- [SECURITY_DMESG_RESTRICT](https://lwn.net/Articles/414813/)：Restrict unprivileged access to kernel syslog. The kernel syslog contains debugging information that is often useful during exploitation of other vulnerabilities, such as kernel heap addresses.  Rather than futilely attempt to sanitize hundreds (or thousands) of printk statements and simultaneously cripple useful debugging functionality, it is far simpler to create an option that prevents unprivileged users from reading the syslog.

  [GRKERNSEC_DMESG](https://xorl.wordpress.com/2010/11/09/grkernsec_dmesg-dmesg-restriction/)：If you say Y here, non-root users will not be able to use dmesg(8) to view up to the last 4kb of messages in the kernel's log buffer. If the sysctl option is enabled, a sysctl option with name "dmesg" is created.

- [INIT_STACK_ALL](https://cateee.net/lkddb/web-lkddb/INIT_STACK_ALL.html)：Initializes everything on the stack with a 0xAA pattern. This is intended to eliminate all classes of uninitialized stack variable exploits and information exposures, even variables that were warned to have been left uninitialized.

  [PAX_MEMORY_STRUCTLEAK](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options)：Forcibly initialize local variables copied to userland.

  By saying Y here the kernel will zero initialize some local variables that are going to be copied to userland.  This in turn prevents unintended information leakage from the kernel stack should later code forget to explicitly set all parts of the copied variable.

  The tradeoff is less performance impact than PAX_MEMORY_STACKLEAK at a much smaller coverage.

  Note that the implementation requires a gcc with plugin support, i.e., gcc 4.5 or newer.  You may need to install the supporting headers explicitly in addition to the normal gcc package.

  [STRUCTLEAK_BYREF_ALL](https://www.openwall.com/lists/kernel-hardening/2019/03/11/2)：the STRUCTLEAK_BYREF_ALL feature "gives the kernel complete initialization coverage of all stack variables passed by reference".

- [SLAB_FREELIST_HARDENED]()：Many kernel heap attacks try to target slab cache metadata and other infrastructure. This options makes minor performance sacrifices to harden the kernel slab allocator against common freelist exploit methods. [Linux kernel 4.14 SLAB_FREELIST_HARDENED 简单分析](https://paper.seebug.org/470/)

#### （2）KSPP项目

#### 漏洞类型：

1. stack overflow and exhaustion

   示例：https://jon.oberheide.org/files/half-nelson.c

   防护：

   - **stack canaries, e.g. gcc's -fstack-protector (v2.6.30) and -fstack- protector-strong (v3.14)**, *best-effort CONFIG selected for compiler*
   - guard pages (e.g. GRKERNSEC_KSTACKOVERFLOW)
     - **vmap stack (v4.9 x86, v4.14 arm64), removal of thread_info from stack (v4.9 x86, v4.10 arm64)**
   - *alloca checking (e.g. PAX_MEMORY_STACKLEAK): Alexander Popov* 进出内核空间时对进程内核栈的数据进行擦除。
   - shadow stacks (e.g. [Clang SafeStack](https://blog.csdn.net/wuhui_gdnt/article/details/52710205)，将原生栈分为两个区域，尝试保护栈上的关键数据：一个安全栈，用于控制流信息以及仅以安全方式访问的数据（通过静态分析确定）。一个用于保存其他数据的非安全栈。这两个栈位于进程地址空间中不同的内存区域，因此防止了非安全栈的溢出破坏安全栈。)

2. integer over/underflow

   示例：

   - https://cyseclabs.com/page?n=02012016
   - http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/

   防护：

   - **check for refcount overflow (v4.11)** (e.g. PAX_REFCOUNT，针对引用计数溢出的加固。实现包括两个部分，一部分是探测引用计数的溢出，一部分是溢出发生时的异常处理。)
     - *refcount_t conversions: Elena Reshetova, Peter Zijlstra, Hans Liljestrand,* *David Windsor*
   - compiler plugin to detect multiplication overflows at runtime (e.g. PAX_SIZE_OVERFLOW, Clang -fsanitize=integer)

3. buffer overflows

   示例：http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html

   防护：

   - runtime validation of copy_{to,from}_user() buffer sizes (e.g. PAX_USERCOPY)
     - **CONFIG_HARDENED_USERCOPY (v4.8)**
     - *Usercopy whitelisting and slab segregation: David Windsor*
   - metadata validation (e.g. glibc's heap protections)
     - **linked-list hardening (based on grsecurity) CONFIG_DEBUG_LIST (v4.10),**
     - **heap freelist obfuscation (based on grsecurity) CONFIG_SLUB_HARDENED (v4.14)**
     - *Heap canaries: Daniel Micay*
     - *Intel MPX: Hans Liljestrand, Elena Reshetova*
   - FORTIFY_SOURCE (inspired by glibc), check str*/mem*() sizes at compile- and run-time
     - **CONFIG_FORTIFY_SOURCE (v4.13)**
     - *Intra-object checking: Daniel Micay*

4. format string injection

   示例：http://www.openwall.com/lists/oss-security/2013/06/06/13

   防护：

   - **Drop %n entirely (v3.13)**
   - detect non-const format strings at compile time (e.g. gcc's -Wformat- security, or better plugin)
   - detect non-const format strings at run time (e.g. memory location checking done with glibc's -D_FORITY_SOURCE=2)
   - (Can we get rid of %p? Stay tuned...)

5. kernel pointer exposure

   示例：

   - examples are legion: /proc (e.g. kallsyms, modules, slabinfo, iomem), /sys, **INET_DIAG (v4.1)**, etc
   - http://vulnfactory.org/exploits/alpha-omega.c

   防护：

   - **kptr_restrict sysctl (v2.6.38)** too weak: requires dev opt-in
   - remove visibility to kernel symbols (e.g. GRKERNSEC_HIDESYM)
   - **obfuscate output of %p (v4.15)**: in dmesg, seq_file, user buffers, etc (e.g. GRKERNSEC_HIDESYM + PAX_USERCOPY)

6. uninitialized variables

   示例：https://outflux.net/slides/2011/defcon/kernel-exploitation.pdf

   防护：

   - *GCC plugin, stackleak: clear kernel stack between system calls (from PAX_MEMORY_STACKLEAK): Alexander Popov*
   - **GCC plugin, structleak: instrument compiler to fully initialize all structures (from PAX_MEMORY_STRUCTLEAK): (__user v4.11, by-reference v4.14)**

7. use-after-free

   示例：http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/

   防护：

   - clearing memory on free can stop attacks where there is no reallocation control (e.g. PAX_MEMORY_SANITIZE)
     - **Zero poisoning (v4.6)**
   - segregating memory used by the kernel and by userspace can stop attacks where this boundary is crossed (e.g. *PAX_USERCOPY*)
   - randomizing heap allocations or using quarantines can frustrate the reallocation efforts the attack needs to perform (e.g. OpenBSD malloc)
     - **Freelist randomization (SLAB: v4.7, SLUB: v4.8)**

#### 利用方法：

1. finding the kernel

   示例：https://github.com/jonoberheide/ksymhunter 也包含内核指针泄露

   防护：

   - hide symbols and kernel pointers (see “Kernel pointer exposure”)
   - kernel ASLR
     - text/modules base: **x86 (v3.14), arm64 (v4.6), MIPS (v4.7),** *ARM: Ard Biesheuvel*
     - memory: **arm64 (v4.6), x86 (v4.8)**
     - PIE: **arm64 (v4.6)**, *x86: Thomas Garnier*
   - runtime randomization of kernel functions
   - executable-but-not-readable memory
     - Initial support: **x86 (v4.6), arm64 (v4.9)**, needs real hardware and kernel support
   - per-build structure layout randomization (e.g. GRKERNSEC_RANDSTRUCT)
     - **manual (v4.13), automatic (v4.14)**

2. direct kernel overwrite

   示例:

   - Patch setuid to always succeed
   - http://itszn.com/blog/?p=21 OverwritevDSO

   防护：

   - Executable memory cannot be writable (CONFIG_STRICT_KERNEL_RWX)
     - **s390, parisc: forever ago**
     - **x86: v3.18 (more completely)**
     - **ARM: v3.19**
     - **arm64: v4.0**
     - **powerpc: v4.13**

3. function pointer overwrite

   示例：

   - https://outflux.net/blog/archives/2010/10/19/cve-2010-2963-v4l-compat-exploit/
   - https://blogs.oracle.com/ksplice/entry/anatomy_of_an_exploit_cve

   防护：

   - read-only function tables (e.g. PAX_CONSTIFY_PLUGIN)
   - make sensitive targets that need one-time or occasional updates only writable during updates (e.g. PAX_KERNEXEC):
     - **__ro_after_init (v4.6)**
     - *write-once memory: Igor Stoppa*
   - **struct timer_list .data field removal (v4.15)**

4. userspace execution

   示例：以上都是

   防护：

   - hardware segregation: **SMEP (x86), PXN (ARM, arm64)**
   - emulated memory segregation via page table swap, PCID, etc (e.g. PAX_MEMORY_UDEREF):
     - **Domains (ARM: v4.3)**
     - **TTBR0 (arm64: v4.10)**
     - **PTI (x86: v4.15)**
   - compiler instrumentation to set high bit on function calls

5. userspace data access

   示例：

   - https://github.com/geekben/towelroot/blob/master/towelroot.c
   - http://labs.bromium.com/2015/02/02/exploiting-badiret-vulnerability-cve-2014-9322-linux-kernel-privilege-escalation/

   防护：

   - hardware segregation: **SMAP (x86), PAN (ARM, arm64)**
   - emulated memory segregation via page table swap, PCID, etc (e.g. PAX_MEMORY_UDEREF):
     - **Domains (ARM: v4.3)**
     - **TTBR0 (arm64: v4.10)**
     - *PCID (x86): Andy Lutomirski*
   - *eXclusive Page Frame Ownership: Tycho Andersen, Juerg Haefliger*

6. reused code chunks——ROP/JOP

   示例：http://vulnfactory.org/research/h2hc-remote.pdf

   防护：

   - JIT obfuscation (e.g. BPF_HARDEN): **eBPF JIT hardening (v4.7)**

   - hardware protected pointers (e.g. *ARM pointer authentication: Mark Rutland*)

   - compiler instrumentation for Control Flow Integrity (CFI):

     - Clang CFI https://clang.llvm.org/docs/ControlFlowIntegrity.html

     - kCFI https://github.com/kcfi/docs

     - GCC plugin: Return Address Protection, Indirect Control Transfer Protection (e.g. RAP)

       https://pax.grsecurity.net/docs/PaXTeam-H2HC15-RAP-RIP-ROP.pdf

#### 各版本更新：

1. [v4.10](https://outflux.net/blog/archives/2017/02/27/security-things-in-linux-v4-10/)
   - PAN emulation, arm64
   -  thread_info relocated off stack, arm64 
   - Linked list hardening
   -  RNG seeding from UEFI, arm64
   -  W^X detection, arm64
2. [v4.11](https://outflux.net/blog/archives/2017/05/02/security-things-in-linux-v4-11/)
   - refcount_t infrastructure
   -  2 refcount_t conversions 
   - read-only usermodehelper 
   - structleak plugin (__user mode)
3. [v4.12](https://outflux.net/blog/archives/2017/07/10/security-things-in-linux-v4-12/)
   - 57 refcount_t conversions
   -  read-only and fixed-location GDT, x86 
   - usercopy consolidation
   -  read-only LSM structures
   -  KASLR enabled by default, x86
   -  stack canary expanded to bit-width of host 
   - stack/heap gap expanded
4. [v4.13](https://outflux.net/blog/archives/2017/09/05/security-things-in-linux-v4-13/)
   - 65 refcount_t conversions 
   - CONFIG_REFCOUNT_FULL 
   - CONFIG_FORTIFY_SOURCE 
   - randstruct plugin (manual mode) 
   - ELF_ET_DYN_BASE lowered
5. [v4.14](https://outflux.net/blog/archives/2017/11/14/security-things-in-linux-v4-14/)
   - 3 refcount_t conversions (bikeshedding stall) 
   - randstruct plugin (automatic mode)
   -  SLUB freelist pointer obfuscation
   -  structleak plugin (by-reference mode) 
   - VMAP_STACK, arm64
   - set_fs() removal progress
   - set_fs() balance detection, x86, arm64, arm
6. v4.15
   - PTI
   - retpoline
   - 35 refcount_t conversions (32 remaining)
   - struct timer_list .data field removal
   - fast refcount overflow protection, x86 (also in v4.14 -stable) 
   - %p hashing
7. Maybe in v4.16
   - 32 refcount_t conversions?
   - usercopy whitelisting 
   - CONFIG_CC_STACKPROTECTOR_AUTO
8. Future
   - stackleak plugin 
   - eXclusive Page Frame Owner 
   - KASLR, arm 
   - SMAP emulation, x86 
   - brute force detection 
   - write-rarely memory 
   - Link-Time Optimization 
   - Clang plugins 
   - Control Flow Integrity
   - integer overflow detection
   - VLA removal (-Werror=vla) 
   - per-task stack canary, non-x86 
   - per-CPU page tables 
   - read-only page tables 
   - hardened slab allocator 
   - hypervisor magic :)

后续的更新可以看看https://outflux.net/blog/，上面有每个linux版本的安全更新说明。



### 参考资料：

[PaX的技术考古之旅](https://hardenedlinux.github.io/system-security/2015/05/23/archeological_hacking_on_pax.html)

[PaX的技术考古之旅——学习](https://blog.csdn.net/volcano3511/article/details/74178359)

[**Brad Spengler**采访——Linux 内核社区是数字军火商、斯拉夫兵工厂甚至 NSA 的最爱](https://www.infoq.cn/article/Linux-PaX-Grsecurity) **Linux Torvalds**

[PaX与KSPP矛盾_HardenedLinux: The way to the Ark](https://hardenedlinux.github.io/announcement/2017/04/29/hardenedlinux-statement2.html)

[KSPP-Linux内核自防护项目的初始文档](https://hardenedlinux.github.io/system-security/2016/05/23/kernel_self_protection.html)

[wiki-SELinux](https://selinuxproject.org/page/Main_Page)

[wiki-AppArmor](https://en.wikipedia.org/wiki/AppArmor)

[wiki-grsecurity](https://wiki.debian.org/grsecurity)

[wiki-Kernel Self Protection Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)

[百度百科-SELinux](https://baike.baidu.com/item/SELinux)

[百度百科-AppArmor](https://baike.baidu.com/item/apparmor)

[Grsecurity/Appendix/Grsecurity and PaX Configuration Options](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options)

[PaX/Grsecurity配置选项](https://hardenedlinux.github.io/system-security/2015/08/17/Grsecurity_catalogue_cn.html)