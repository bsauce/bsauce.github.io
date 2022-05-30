---
layout: post
title: 【bsauce读论文】2021-USENIX-EXPRACE-采用中断机制来利用多变量竞争漏洞
categories: [Paper]
description: 【bsauce读论文】2021-USENIX-EXPRACE-采用中断机制来利用多变量竞争漏洞
keywords: Kernel exploit, Paper
---

# 【bsauce读论文】2021-USENIX-EXPRACE-采用中断机制来利用多变量竞争漏洞

本文提出的技术最开始在2020 BlackHat上展示，名字叫[Exploiting Kernel Races Through Taming Thread Interleaving](https://i.blackhat.com/USA-20/Thursday/us-20-Lee-Exploiting-Kernel-Races-Through-Taming-Thread-Interleaving.pdf)，今年又在2021 USENIX会议上发表出来[ExpRace: Exploiting Kernel Races through Raising Interrupts](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-yoochan)，实验材料尚未公布。

**目标**：对于多变量竞争漏洞，其触发时指令的执行顺序很特殊，没有人工干预的话很难触发。

**解决**：提出ExpRace，采用中断机制（rescheduling IPI，TLB shootdown IPI，membarrier IPI，hardware interrupts）来增大竞争窗口。

**实验**：对10个真实CVE进行测试，全部在10~118s内成功利用；如果不利用ExpRace的话24小时都不能利用成功。

**贡献**：分析内核数据竞争漏洞的可利用性；提出采用多种中断机制来利用多变量竞争漏洞；对10个真实的CVE进行测试，全部利用成功。

---

## 1.内核竞争漏洞的可利用性

![Figure 1-multi-variable race](\images\posts\ExpRace\Figure 1-multi-variable race.png)

内核竞争漏洞可分为两类，一是单变量竞争，二是多变量竞争，多变量竞争又分为包含式和非包含式。

#### 1.1 单变量竞争

**描述**：见`Figure 1-a`，3条竞争指令A、B、C访问同一变量，若B在AC之间修改了变量M，则C会获得和A不同的M值，如果多线程竞争使得指令执行顺序为A->B->C，就会触发竞争漏洞。

**利用方法**：蛮力攻击。用户层不断调用Syscall~x~和Syscall~y~。利用成功率$P_{single}=\frac{T_y}{T_{Syscall_x}}$  （通常情况下${T_{Syscall_x}} \ge T_y$），尽管P~single~看上去很低，但蛮力攻击还是很有效。

#### 1.2 多变量竞争

**描述**：见`Figure 1-b`，A、B访问同一变量M~1~，C、D访问同一变量M~2~，如果C在A、D之间访问M~2~，则D点获得不同的M~2~值，导致原子违例。原子违例的前提条件是严格按A->B->C->D的顺序执行。

**原因**：内核访问变量有一种常见的模式，这很容易产生多变量竞争漏洞。(i) 先搜索数据位置，例如枚举数据结构（list 或 tree）；(ii) 根据虚地址读取数据或更新数据。

**利用挑战**：通过蛮力攻击，使得T~x~位于T~y~中（假设$T_{Syscall_x} \leq T_{Syscall_y}$）。可通过线段图来进行理解，如果$T_x \geq T_y$（非包含式），则竞争几乎不可能成功。
![1](\images\posts\ExpRace\1.png)
**实例-CVE-2017-15265**：见Figure 2。

- 分析：Task~y~采用create命令创建缓冲区port，并插入到`p->list`，对应A点；然后将用户输入拷贝到`port->name`，对应D点。Task~x~采用delete命令释放port，先从`p->list`找到相应的port，对应B点；再释放，对应C点。
- 竞争变量：`p->list` 和 port
- 漏洞：如果按照A->B->C->D，则会导致UAF。
- 利用：需要触发UAF 3次。首先采用`msgsnd()`喷射file指针；然后触发漏洞来部分覆写`snd_seq_queue->tickq`，以泄露喷射的file指针；接着，触发漏洞来覆写iovec结构，构造任意读，读取 `struct file`中的`struct *f_cred`；最后，触发漏洞来覆写iovec，构造任意写，修改cred提权。
- 问题：T~x~比T~y~大太多（12倍），几乎不可能竞争成功。

![Figure 2-CVE-2017-15265](\images\posts\ExpRace\Figure 2-CVE-2017-15265.png)

---

## 2.概率模型与中断分类

**本文目标**：针对非包含的多变量竞争（non-inclusive multivariable race，也即$T_x \geq T_y$的情况），采用中断来增大AD竞争窗口（也即T~y~的值）。

![Figure 3-enlarge approach](\images\posts\ExpRace\Figure 3-enlarge approach.png)

**竞争成功率（概率模型）**：T~E~—中断处理耗时；T~y'~=T~y~+T~E~，称T~y'~为竞争窗口（race window）。

- （1）若T~x~肯定位于Ty'中，只需看中断是否恰好出现在T~y~中间；
- （2）若T~x~<T~y'~<T~syscallx~，需保证中断出现在T~y~中间，且T~x~位于T~y'~中间；
- （3）若T~x~>T~y'~，则很难竞争成功。

![2](\images\posts\ExpRace\2.png)

**中断分类**：主要分为两类。
（1）硬件中断IRQ（Hardware interrupt request）：通过IO-APIC，从外部硬件设备向OS发送信号；
（2）处理器间中断IPI（Inter Processor Interrupt）：从某个CPU核向其他核发送信号，例如rescheduling IPI, wake-up IPI, stop IPI, function call IPI。

![Table 2-list exploit methods](\images\posts\ExpRace\Table 2-list exploit methods.png)

---

## 3.中断利用方法

#### 3.1 Reschedule IPI

**CONFIG_PREEMPT**：设置该选项，表示如果需要调度，则会调用schedule，内核态将被抢占。

**介绍**：Reschedule IPI由内核函数`smp_send_reschedule()`来发送，包含参数cpu，来指定哪个核将接收到IPI。

**用户层调用**：触发`smp_send_reschedule()`的用户态函数有两种。第1种系统调用只需要1个进程，且相同时间内能够发送更多的 IPI，所以采用`sched_setaffinity()`调用。

- 一是用户态调用`sched_setaffinity()`，参数是pid和mask，最终设置在`smp_send_reschedule()`的cpu上运行指定pid进程；
- 二是通过唤醒等待线程，首先绑定特定核与task A，通过`read()`将线程状态改为等待状态，然后从task B调用`write()`唤醒等待的线程，内核会将task A的进程状态从waiting改为running，并向task A所在的核发送 reschedule IPI。

**方法**：创建3个task，Task~x~ / Task~y~ / Task~int~，分别在核心C0 / C1 / C2上运行（Task~x~和Task~int~可以是Task~y~的子线程或子进程，Task~x~和Task~y~负责触发竞争），Task~int~负责调用`sched_setaffinity(C1)`—B点，内核会将Task~int~从C2迁移到C1运行队列，并向C1发送reschedule IPI—C点。如果C1在竞争窗口Ty中接收到 reschedule IPI，就会转而去处理IPI—D点，然后C1切换到Task int的上下文—E点，最后再调度回来—F点。这样就增大了T~y~竞争窗口。

![Figure 4-Reschedule IPI exploit](\images\posts\ExpRace\Figure 4-Reschedule IPI exploit.png)

#### 3.2 Non-Reschedule IPI

**分类**：根据发送命令的不同，将非调度的IPI分为两类，一是TLB管理，二是内存栅栏。

##### 3.2.1 TLB Shootdown IPI

**Translation Lookaside Buffer (TLB)**：地址转换旁路缓冲存储器。虚地址转换为物理地址，每个核都有自己的TLB，需要进行核间同步。OS实现TLB shootdown机制来确保TLB正确同步。

**原理**：如果某核更新了TLB入口，则通过向具有相同入口的其他核发送TLB shootdown IPI，告知其刷新TLB。`mm_struct->cpu_bitmap`负责存储含相同页表入口的核。

**用户层调用**：`mprotect()`或`munmap()`修改内存权限，则内核首先刷新当前核的TLB，再向其他核发送IPI。

**方法**：

- （1）Task~x~和Task~y~必须位于不同进程，如果二者位于同一进程（不同线程），二者会指向同一`mm_struct`，且`cpu_bitmap`会将C0和C1都设置，导致IPI会发给C0和C1。Task~int~则必须和Task~y~位于同一进程，这样才能有相同的页表入口（便于发送TLB Shootdown IPI）。
- （2）Task~y~或 Task~int~调用`mmap()`分配内存M。
- （3）Task~x~和Task~y~竞争时，Task~int~调用`mprotect(M, ...)`修改M的权限—B点，内核先刷新C2的TLB，并向C1发送function call IPI（因为M对应C1的`mm_struct->cpu_bitmap`已经设置了），如果C1在竞争窗口间收到IPI，就会停止Task~y~并调用`native_flush_tlb_one_user()`来处理IPI。这样就增大了T~y~竞争窗口。

![Figure 5-TLB shootdown exploit](\images\posts\ExpRace\Figure 5-TLB shootdown exploit.png)

##### 3.2.2 Memory Barrier IPI

**membarrier**：多处理器系统中，控制内存访问顺序。membarrier需要激活特定线程上的内存栅栏，所以要用到IPI机制来通知运行特定线程的核。

**用户层调用**：`membarrier()`，可以从用户层直接发送 memory barrier IPI。

**方法**：

- （1）Task~x~和Task~y~位于不同进程，才能拥有不同的mm，Task~x~由Task~y~ fork产生，Task~int~由Task~y~调用 `pthread_create()` 产生；
- （2）Task~y~或Task~int~调用`membarrier(REGISTER)`来注册内存栅栏；
- （3）Task~x~ 和Task~y~ 触发竞争，Task~int~调用`membarrier(EXPEDITED)`，内核就会向C1发送 membarrier IPI（因为C1上的Task~y~和Task~int~引用了相同的`mm_struct`）;
- （4）Task~y~收到IPI后，就会调用`ipi_mb()`来处理IPI，这样就增大了T~y~竞争窗口。

![Figure 6-membarrier IPI](\images\posts\ExpRace\Figure 6-membarrier IPI.png)

#### 3.3 Hardware Interrupts

**硬件中断IRQ**：通过IO-APIC从外设发送到处理器的电子信号。

**原理**：

- 发出IRQ后，中断控制器将中断发给指定的CPU核（Linux中通过bit掩码确定目标核，Windows通过轮询确定目标核），相应的CPU核执行中断服务程序（ISR）。

- 可通过读取procfs确定bit掩码，确定处理指定外设请求的目标核，例如，默认内核配置中，enp2s0设备对应IRQ122，由CPU core 11处理。

**发送方式**：不能直接从用户层发送，先从用户向设备发送请求，设备再向内核发送IRQ。两种方式——一是发送TCP请求到以太设备，设备再向内核发送IRQ来处理包；二是采用文件读写发送disk请求，disk控制器设备（如AHCI设备）向内核发送IRQ，表示disk请求已完成。

**方法**：

- （1）Task~x~ 和Task~int~ 可以跟Task~y~ 是不同线程或进程，硬件中断与进程线程无关，先读取`/proc/irq/#/smp_affinity`获得CPU核号（处理以太设备的IRQ的核号，暂设为C1）；
- （2）Task~x~和Task~y~ 触发竞争时，Task~int~向自身发送TCP请求（外部IP—局部机器）—对应B点；
- （3）以太设备向C1发送IRQ—C点；
- （4）若C1在T~y~中间收到IRQ，就会调用相应的ISR来处理—D点，这样就增大了T~y~竞争窗口。

![Figure 7-HW interrupt exploit](\images\posts\ExpRace\Figure 7-HW interrupt exploit.png)

---

## 4.其他操作系统上的中断利用

**说明**：membarrier是Linux独有，所以不用研究。这些中断在Windows中都可用，Mac OS中Reschedule IRQ不可用，HW中断没测试。

**Windows**：

- Reschedule IPI：Windows中，优先级比当前线程更高的线程才能被调度。改进，用户层使用`SetThreadAffinityMask()`调用替代`sched_setaffinity()`，并额外调用`SetThreadPriority()`来设置更高的优先级。
- TLB Shootdown IPI：需用到`VirtualAlloc()`、`VirtualProtect()`、`VirtualFree()`来分配、修改、释放内存页。
- HW Interrupt：不同点是，Windows没有特定CPU来处理某个外设的IRQ，而是采用轮询来确定CPU，所以理论上，k个CPU的话，增大Ty的几率为Linux的1/k

**Mac OS X**：

- Reschedule IPI：不可用。
- TLB Shootdown IPI：采用相同的函数mmap()、mprotect()、munmap()能够增大Ty。
- HW Interrupt：Mac OS没有提供足够的信息来研究其硬件断点。

![Table 3-other OSes](\images\posts\ExpRace\Table 3-other OSes.png)

---

## 5.实验评估

**实验设计**：选取10个非包含式多变量竞争漏洞进行测试，选取的漏洞见`Table 1`，其中CVE-2019-1999 和 CVE-2019-2025 含有公开exp。每个漏洞最多尝试利用24h。

![Table 1-CVE](\images\posts\ExpRace\Table 1-CVE.png)

**实验结果**：结果见`Table 4`。不用ExpRace的话，10个CVE在24h内全部利用失败。

- Reschedule成功3个，都在66s内。
- membarrier IPI成功3个。CVE-2019-6974, CVE-2019-1999, 11eb85ec, 1a6084f8, e20a2e9c是由于T~y'~太小。
- TLB shootdown成功7个。
- hardware interrupts成功10个。

**说明**：membarrier 和 TLB shootdown 不能用于 CVE-2019-6974 和 da1b9564，因为这两个漏洞要求两个导致竞争的syscall位于同一进程。

![Table 4-Exploit result](\images\posts\ExpRace\Table 4-Exploit result.png)
