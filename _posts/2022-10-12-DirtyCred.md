---
layout: post
title: 【bsauce读论文】2022-CCS-DirtyCred: Escalating Privilege in Linux Kernel
categories: Paper
description: 【bsauce读论文】2022-CCS-DirtyCred: Escalating Privilege in Linux Kernel
keywords: Kernel exploitation, Paper
---


# 【bsauce读论文】2022-CCS-DirtyCred: Escalating Privilege in Linux Kernel

## 1. 介绍

**简介**：本文灵感来自 CVE-2022-0847 DirtyPipe漏洞，不需要绕过现有的防护机制就能成功提权，但问题是只要该漏洞被修补后，就无法再利用，并不通用。所以本文提出了 DirtyCred，一种新的通用漏洞利用方法，不用依赖Linux的pipeline机制，只需利用堆内存破坏类型的漏洞，来交换非特权和特权内核凭证（`cred`/`file` 对象），就能达到和DirtyPipe类似的利用效果。本方法不仅可以提权，还能进行容器逃逸。本文还提出了防护机制，将内核中的高权限凭证和低权限凭证隔离开来（高权限对象存放在vmalloc分配的区域，正常区域存放低权限对象），该机制带来的系统开销可以忽略不计。

**贡献**：

- （1）提出了一种新的漏洞通用利用方法 DirtyCred，能够绕过主流防护机制并提权；
- （2）验证了DirtyCred在真实漏洞上的可用性，且存在很多DirtyCred所需的可利用对象；
- （3）提出了防护机制。

## 2. 背景

### 2-1. Dirty Pipe

**漏洞说明**：参见 [【kernel exploit】CVE-2022-0847 Dirty Pipe 漏洞分析与利用](https://bsauce.github.io/2022/04/03/CVE-2022-0847/) 。`splice`调用将包含文件的页面缓存（page cache），链接到pipe的环形缓冲区 [pipe_buffer](https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/pipe_fs_i.h#L26) （保存着实际存放数据的物理页地址）时，[copy_page_to_iter_pipe()](https://elixir.bootlin.com/linux/v5.16.10/source/lib/iov_iter.c#L384) 和 [push_pipe()](https://elixir.bootlin.com/linux/v5.16.10/source/lib/iov_iter.c#L547) 函数都没有将 [pipe_buffer](https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/pipe_fs_i.h#L26) -> `flag` 标志位初始化（**变量未初始化漏洞**，若该标志位为 `PIPE_BUF_FLAG_CAN_MERGE`，表示这次写入的数据可以直接合并到对应的物理页中）。由于该值可能默认为 `PIPE_BUF_FLAG_CAN_MERGE`，导致后续调用 `pipe_write()` 写入数据时误以为write操作可合并，从而将新数据与文件页面缓存上的数据合并，导致任意文件覆盖漏洞。

**利用总结**：

- （1）创建一个管道（不指定 `O_DIRECT` ）；
- （2）将管道填充满（通过 `pipe_write()`操作每次写入整页），这样所有的 pipe 缓存页都初始化过了，`pipe->flag` 被初始化为`PIPE_BUF_FLAG_CAN_MERGE` ；
- （3）将管道清空（通过 `pipe_read()` 操作），这样通过splice 系统调用传送文件的时候就会使用原有的初始化过的buf结构；
- （4）打开待覆写文件（例如只读文件 `/etc/passwd`），调用 `splice()` 将往pipe写入1字节（将只读文件的页面缓存加载进pipe中，这样才能将page cache索引到`pipe_buffer`，此时每个结构的  `pipe_buffer->flag == PIPE_BUF_FLAG_CAN_MERGE`，还是原先残留的值，导致后续的write直接污染本不该被修改的文件页面缓存，使得只读文件在内存中的数据被篡改 ）；
- （5）调用 `write()` 继续向pipe写入小于1页的数据（实际调用 `pipe_write()`），这时就会覆盖到文件缓存页了，暂时篡改了目标文件。（只要没有其他可写权限的程序进行write操作，该页面并不会被内核标记为“dirty”，也就不会进行页面缓存写会磁盘的操作，此时其他进程读文件会命中页面缓存，从而读取到篡改后到文件数据， 但重启后文件会变回原来的状态）

### 2-2. 内核凭证（credential）

**分类**：内核中包含权限信息的对象，例如 `cred`/`file`/`inode`，本文用到的是 `cred`/`file` 对象，因为 `inode` 对象只有在文件系统上创建新文件时才会分配，不适合进行内存布局。

**cred**：包含 `UID` 成员，表示任务的权限，`UID == GLOBAL_ROOT_UID` 表示任务具有root权限；`cred` 还包含 capability，表示任务的细分权限，例如 `CAP_NET_BIND_SERVICE` 表示任务可以将socket绑定到网络域的高权限端口。如果需要修改 `cred`，先拷贝一份并修改copy，最后将`cred`指针指向该copy。

**file**：每个文件都包含 UID/GID、访问权限、capability，可执行文件还有 SUID/SGID表示许可（用户运行时只能采用自身的权限） 。每个文件都关联1个 `inode` 对象来表示凭证。当某个任务打开一个文件，进行文件访问之前，内核调用 `inode_permission()` 来检查inode和相应的许可；文件打开之后，内核解除凭证和`inode`对象的链接，将凭证绑定到 `file` 对象上（所以`file`结构只保存已被打开的文件的信息）。`file` 对象不仅保存凭证，还保存文件的读写许可。

### 2-3. 内存管理

**Generic Caches** / **Dedicated Caches**：漏洞一般发生在通用cache中，而 `cred`/`file` 对象则位于专有cache中。内核中可通过 `$ sudo cat /proc/slabinfo` 命令进行查看。

### 2-4. 威胁模型

目标是利用堆内存破坏漏洞（OOB/UAF/DF）来提权；启用 v5.15主流的保护机制，KASLR/SMAP/SMEP/CFI/KPTI，假设不能采用硬件侧信道来辅助利用。

## 3. Overview & Challenge

### 3-1. Overview

**CVE-2021-4154漏洞**：CVE-2021-4154 是UAF漏洞，`fs_context` 对象引用了 `file` 对象，本漏洞会在file对象仍在使用的情况下，将file对象错误释放（引用计数为0时自动释放）。

**利用步骤**：本例是采用 `file` 对象完成利用，也可以采用 `cred` 对象。

- （1）打开可写的文件`/tmp/x`，就会分配可写的 `file` 对象，在通过写许可检查之后后，进行实际写操作之前暂停；
- （2）利用漏洞释放该file对象；
- （3）打开只读文件`/etc/passwd`，就会分配新的 `file` 对象，占据旧的 `file` 对象，继续写入就能往只读文件写入内容（例如写入 `hacker:x:0:0:root:/:/bin/sh` 就能提权）。

![Figure1-Exploit Overview](/images/posts/DirtyCred/Figure1-Exploit Overview.png)

### 3-2. Challenge

**挑战**：

- （1）将不同的漏洞能力（堆漏洞 OOB/UAF/DF）转化为有利于凭证对象交换的原语（错误释放原语，先释放低权限对象，也即有写许可的 `file` 对象，再重新分配高权限对象占据，也即只有读许可的 `file` 对象）。
- （2）需要增大时间窗口，在权限检查和实际写入之间暂停，以进行 `file` 对象替换。方法是采用 userfaultfd、FUSE和文件系统的锁来增大时间窗口。
- （3）使普通用户（非特权）能触发分配具有高权限的凭证对象，这样才能利用交换凭证对象来提权。方法是采用不同的内核机制，从用户层和内核层发起特权线程，以分配具有高权限的凭证对象。

**DirtyCred优点**：一是通用性强，适用于任意堆相关的漏洞；二是降低了exp适配难度，同一exp可用于不同版本和架构的内核；三是可以绕过主流的防护机制，例如CFI/KASLR/SMEP/SMAP/KPTI等。

## 4. 挑战1-转化漏洞能力

### 4-1. OOB & UAF write

**方法**：首先找到一个 victim 对象，和漏洞对象位于相同cache且包含一个凭证指针；再利用漏洞将 victim 的凭证指针的最后两字节覆写为0，这样该指针就可能指向内存页开头的另一个凭证对象；这样就有2个指针指向内存页的第1个凭证对象，可以释放该对象两次，接下来就能采用 CVE-2021-4154 相同的利用方法。（其实可以直接通过被篡改的凭证指针将首个凭证对象释放，再用高权限凭证对象占据该位置）。

**问题**：一是该页的地址的最低2字节都为0的概率是1/16；二是如果有 freelist 保护怎么办，好像不是问题；三是漏洞可能不允许只覆写最后2字节，那怎么弄，还得先泄露堆地址。

![Figure2-OOB-UAF-pivoting](/images/posts/DirtyCred/Figure2-OOB-UAF-pivoting.png)

### 4-2. DF

**方法**：一般 Double-Free 发生在通用cache中，而内核凭证位于 dedicated cache 中，所以这里需要进行 cross-cache 内存布局。内核会回收未使用的内存页，然后分配给其他需要更多空间的cache。

- `a-d`：两次触发DF，获得2个指向同一漏洞对象的悬垂指针（`ptr1'` / `ptr2'`）；
- `e`：将该通用cache的内存页全部释放归还给页管理器，这样该内存页就可以分配给 `dedicated cache` （存放凭证对象）；
- `f`：分配大量凭证对象（特殊cache）占据漏洞对象对应的空闲块，现在有3个指针指向该内存块了（2个悬垂指针和一个victim对象中的凭证指针，悬垂指针可能未对齐，指向凭证对象的内部）；
- `g`：利用其中1个悬垂指针（`ptr2'`）释放凭证对象，创造空洞；
- `h`：分配新的低权限凭证对象占据该位置；
- 剩余1个悬垂指针（`ptr1'`）指向低权限凭证对象，再次释放后就能用高权限凭证对象替换低权限凭证对象了。

**问题**：悬垂指针 `ptr2'` 指向非对齐的 `dedicated cache`，释放时也是调用普通函数 `kfree()`，如何确认释放的就是凭证对象呢？这里直接引用 [blog](https://kiprey.github.io/2022/10/dirty-cred/) 的说明，通过查阅 slab 分配器的 kfree 逻辑，发现它的释放逻辑与被释放地址高度相关。首先会尝试根据被释放地址获取其对应的 `slab_cache` 结构，然后再根据结构中所存放的信息来释放对应的 object size。换句话说，如果 kfree 释放的地址在 `generic cache` 中，那就会走 `generic cache` 的释放逻辑；如果是在 `dedicated cache` 中，那就会走 `dedicated cache` 的释放逻辑。这么做或许是为了提高可用性，使得释放两个不同 cache 的内存块可以使用同一个 kfree 接口。

![Figure3-DF-pivoting](/images/posts/DirtyCred/Figure3-DF-pivoting.png)

## 5. 挑战2-增大时间窗

### 5-1. 利用 Userfaultfd & FUSE

**技术**：采用 Userfaultfd 和 FUSE。前者允许用户空间处理页错误（注意，从内核 v5.11 开始，用户层的 userfaultfd 是默认禁用的）；后者允许用户实现用户空间的文件系统，用户可以注册handler函数来响应文件操作的请求。只要存在从用户向内核拷贝数据的程序点，二者都可以暂停内核的执行。

**v4.13版本以前**：DirtyCred调用 syscall `writev` （vectored I/O）进行写文件，和 `write` 不同的是，`writev` 先读取 `iovec` 结构（包含用户空间的写地址和写长度），再进行实际写入。在 v4.13 版本以前，`vfs_writev()` 先检查写许可（Line 10~13），再读取 `iovec` 结构（Line 18），这样我们利用 Userfaultfd / FUSE 在 Line 18 处暂停即可。

![List1-vfs_writev-before 4.13](/images/posts/DirtyCred/List1-vfs_writev-before 4.13.png)

**v4.13版本以后**：`vfs_writev()` 代码改变了，先读取 `iovec` 结构（Line 6），再检查写权限（Line 10~13），这样的话在 Line 6 处暂停就没有用了。怎么解决呢？

![List2-vfs_writev-after 4.13](/images/posts/DirtyCred/List2-vfs_writev-after 4.13.png)

**解决**：Linux 中文件系统是以多层形式实现，即高层接口调用底层函数来实现操作，不同的文件系统会实现不同的底层接口。例如，List3 中顶层接口函数 `generic_perform_write()` 中，Line 16 进行实际写；但在实际写之前，内核会触发 `iovec` 这个用户数据的页错误（Line 10），可以在此处暂停。

![List3-generic_perform_write()-high level write](/images/posts/DirtyCred/List3-generic_perform_write()-high level write.png)



### 5-2. 利用文件系统锁

**文件系统锁**：文件系统不允许两个进程同时写同一个文件，采用锁机制来实现（参见 `List 4`，调用 `generic_perform_write()` 进行实际写之前需先获得锁）。

**方法**：进程A/B同时写入同一文件，但A先获得锁，写入大量数据（以增大时间窗，如果写入4G的数据可以使进程等待数十秒），B已经完成权限检查后等待获取锁（Line 6）。这样B的时间窗就增大了，可以进行凭证对象替换。

![List4-write in ext4](/images/posts/DirtyCred/List4-write in ext4.png)

## 6. 挑战3-分配高权限对象

### 6-1. 从用户空间

**cred**：低权限用户可以执行具有SUID权限的binary（为root用户所拥有），例如 su/ping/sudo/mount/pkexec，或者频繁创建特权级守护进程（例如sshd），就会分配特权cred对象。

**file**：直接打开具有只读权限的文件即可（例如 `/etc/passwd`）。

### 6-2. 从内核空间

**特点**：内核发起新线程时，会复制父进程，包括cred对象（具有和父进程相同的权限）。

**方法**：两种方法，一是给内核工作队列创建大量任务，就会创建新的内核线程来执行任务；二是调用 usermode helper，这是一种允许内核创建用户模式进程的机制，例如将内核模块加载到内核空间（内核在**加载内核模块**时，需要**在内核层执行 modprobe 程序**，来**在标准安装驱动路径下搜索目标驱动**。）。

## 7. 实验评估

**环境**：Linux v5.16.15。

### 7-1. 可用对象

**可用对象**：OOB/UAF 需要用到包含 `cred`/`file` 指针的对象，才能将漏洞能力转化为错误释放。

**搜索方法**：首先通过结构定义筛选出包含 `cred`/`file` 指针的对象；找到分配路径；找到释放路径；确保用户可控（采用 syzkaller fuzz 来验证是否可达，有些内核模块 syzkaller 没有支持的模板，则采用人工分析来确认）。

**结果**：找到很多可用对象。

![Table1-Exploitable object](/images/posts/DirtyCred/Table1-Exploitable object.png)

### 7-2. 测试真实漏洞

**CVE挑选原则**：挑选2019年以来的漏洞，这是为了测试内核最先进的exploit缓解技术；只选取堆内存破坏漏洞；去除不能复现崩溃的漏洞；去除需要安装特定硬件才能触发的漏洞。最终选取24个CVE。

**结果**：成功利用16个漏洞，其中8个OOB或UAF，8个DF（所有DF全部成功利用）。

**失败案例**：失败的OOB都是虚拟内存上的溢出，也即vmalloc分配的内存；3个UAF失败，其中CVE-2022-24122只能 UAF read，CVE-2019-2215 和 CVE-2019-1566 的漏洞能力无法覆写可用对象的credential指针。

![Table2-Tested CVE](/images/posts/DirtyCred/Table2-Tested CVE.png)

## 8. 防护机制

**现有防护机制**：现有机制不能防护DirtyCred的原因：一是不违反CFI；二是不依赖特定内核对象（有很多可用对象）；三是不用篡改凭证，而是替换凭证，不影响凭证完整性；四是由于采用交换凭证（同一种类的对象），不受内核对象隔离机制的影响，例如AUTOSLAB [34] / xMP [44]。

**方法**：隔离高权限和低权限凭证对象。高权限对象存放在虚拟内存中（virtual memory region），也即调用 vmalloc 分配的内存，范围是 `VMALLOC_START ~ VMALLOC_END` ；低权限对象存放在正常内存中（direct-mapped memory region），二者不会重叠。注意， vmalloc 保证**虚拟地址空间上连续**（需要配置页表，所以速度会慢一点），kmalloc 保证分配的内存在**物理地址空间上连续**。

**实现**：修改内核分配 `cred`/`file` 对象的代码，如果检测到 `UID == GLOBAL_ROOT_UID` 或者打开了具有写权限的文件，则调用 vmalloc 来存放 `cred`/`file` 对象。如果在内核运行时将 UID 修改为 `GLOBAL_ROOT_UID`，则将高权限 `cred` 对象拷贝到 vmalloc 区域再修改，不能直接修改。

**评估性能影响**：采用 LMbench v3.0 [41] 测试 syscall 和系统I/O 的延迟和带宽，采用 Phoronix Test Suite [42] 测试真实应用程序的性能。发现该保护机制带来的性能开销可以忽略不计。

## 9. 讨论 & 未来工作

**容器逃逸**：本文是利用 `file` 对象来篡改高权限文件，但容器中没有这样的文件用来切换命名空间。文章 [ Using the Dirty Pipe Vulnerability to Break Out from Containers](https://www.datadoghq.com/blog/engineering/dirty-pipe-container-escape-poc/) 提出，可以被动等待 `runC` 进程，并通过覆写该进程来执行root命令。DirtyCred 可以利用 `file` 对象交换机制来覆写 `runC` 进程，实现容器逃逸；而利用 `cred` 对象则不需要被动等待，首先通过替换 `cred` 对象将权限提升为 `SYS_ADMIN`，再采用 [Privileged Container Escape - Control Groups release_agent](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html) 提出的方法，加载一个 cgroup 并利用 `notify_no_release` 机制来执行 root 命令。

**Android提权**：虽然 Android 是基于Linux内核的，但是更难提权，因为有更严格的访问控制和最新防护机制 [[19](https://source.android.com/devices/tech/debug/kcfi)]。DirtyCred 有两种方法提权Android，一是交换进程凭证；二是先利用 `file manipulation` 能力才覆写共享系统库，这样就能从沙箱中提权，然后在内核模块上写入 恶意代码，实现任意读写，最终关闭 SELinux 机制。作者实现了一个 Android 0-day exp 的撰写并获得了 Google 的致谢。

**跨版本/架构利用**：exp能够跨版本通用的原因，一是不需要泄露内核基址来绕过KASLR；二是不需要构造ROP。

**其他能力转化方法**：前面提到需要将漏洞能力转化为有利于 DirtyCred 的原语（错误释放凭证对象），但有些OOB只能覆写 vmalloc 虚拟内存，无法转化。例如 CVE-2021-34866，但是有一篇 [writeup](https://github.com/HexRabbit/CVE-writeup/tree/master/CVE-2021-34866) 可以将 vmalloc 越界写转化为任意地址读写，因此也能转化为DF能力，DirtyCred 很有可能完成利用。

**稳定性**：影响exp稳定性的因素主要有两点，一是漏洞能力转化时的内存布局；二是漏洞触发的稳定性。

**TOCTOU**： source code detection, postmortem detection, system call interposition, intra/inter-process memory consistency, transactional system calls, sandbox filesystems 都不影响。



## 参考

[Markakd/DirtyCred - github](https://github.com/Markakd/DirtyCred)

[DirtyCred: Escalating Privilege in Linux Kernel - ACM CCS 2022](https://zplin.me/papers/DirtyCred.pdf)

[浅析 Linux Dirty Cred 新型漏洞利用方式](https://kiprey.github.io/2022/10/dirty-cred/)