---
layout: post
title: 【bsauce读论文】2024-NDSS-SyzBridge-Linux发行版内核漏洞可利用性评估
categories: Paper
description: 作者调研了43个Linux发行版和230个漏洞，在发行版内核上复现上游PoC，在root权限下成功复现19.1%，非root权限下只成功复现0.9%。**大部分高危漏洞在下游内核中无法复现**。本文开发了**SyzBridge，自动调整上游PoC以适应各种下游发行版内核，来真实反映内核漏洞的危害程度**，并集成了SyzScope工具（识别高危的利用原语）。
keywords: Kernel exploit, Paper
---

# 【bsauce读论文】2024-NDSS-SyzBridge：Linux发行版内核漏洞可利用性评估

## 基本信息

- **原文标题**：SyzBridge: Bridging the Gap in Exploitability Assessment of Linux Kernel Bugs in the Linux Ecosystem
- **原文作者**：Xiaochen Zou, Yu Hao, Zheng Zhang, Juefei Pu, Weiteng Chen, Zhiyun Qian
- **作者单位**：UC Riverside, Microsoft Research
- **关键词**：Linux内核, 漏洞可利用性, 自动化评估, SyzBridge
- **原文链接**：https://dx.doi.org/10.14722/ndss.2024.24926
- **开源代码**：https://github.com/seclab-ucr/SyzBridge

## 1. 论文要点

**论文简介**：作者调研了43个Linux发行版和230个漏洞，在发行版内核上复现上游PoC，在root权限下成功复现19.1%，非root权限下只成功复现0.9%。**大部分高危漏洞在下游内核中无法复现**。本文开发了**SyzBridge，自动调整上游PoC以适应各种下游发行版内核，来真实反映内核漏洞的危害程度**，并集成了SyzScope工具（识别高危的利用原语）。

**实验**：测试SyzBridge，在发行版内核上测试230个上游内核漏洞，root权限和非root权限下，触发率分别提升61%和1300%。集成SyzScope后，测试了282个上游高危漏洞，发现有53个漏洞在下游内核的普通权限下可利用（见Table VI），原先只有5个有CVE编号的被认定为可利用。

**本文主要解决以下问题**：

- （1）为什么上游PoC无法在下游内核中复现，如何避免？
- （2）是否可以在非root权限下复现？ 

## 2. 案例分析

本漏洞是OOB write，在Ubuntu上以root权限运行PoC无法复现，SyzBridge找到了原因并在Ubuntu上生成了新PoC。

**漏洞复现失败原因**：`km_state_notify()`遍历`xfrm_km_list`全局链表中的`xfrm_mgr`对象，并调用相应的`notify()`函数（第7行，漏洞函数）；`xfrm_register_km()`函数负责初始化`xfrm_km_list`全局链表（第14行）。在上游内核中，在内核启动时加载`xfrm_user`模块时，会自动调用该初始化函数；但在Ubuntu默认配置中，不会加载该模块，所以漏洞无法复现。

![1-Motivating_Example](/images/posts/SyzBridge/1-Motivating_Example.png)

**SyzBridge主要工作**：

- **分析PoC失败原因**：通过比较Ubuntu和上游内核的trace，Ubuntu默认是`pfkey`模块负责notify，所以默认会调用`pfkey_send_notify()`，而上游内核会调用`xfrm_send_state_notify()`。SyzBridge会收集trace并自动定位未匹配的trace node（node 3），识别缺失的函数`xfrm_send_state_notify()`及其所属的`xfrm_user`模块，然后通过`modprobe`加载该模块，PoC就能触发漏洞。

- **加载模块和降权方法**：`modprobe`加载模块需要root权限，SyzBridge利用内核的内部机制来加载模块，无需root权限；SyzBridge可通过识别内核安全检查、使用用户命名空间，来降低使用network模块的权限。
- **整合SyzScope**：SyzBridge整合SyzScope，以全面评估下游发行版中的漏洞可利用性，该分析结果有利于构造EXP。

## 3. 探索性实验

**实验设置**：

- **漏洞选取**：选取syzbot上230个含C PoC的漏洞。

- **Linux发行版选取**：Ubuntu, Fedora, Debian, Suse 及其子版本共43个版本。
- **测试内容**：先测每个发行版在root权限下PoC是否成功触发，若成功则测在非root权限下是否成功。

**实验结果**：只有19.1%的漏洞影响到下游内核，0.9%的漏洞能在非root权限下触发，表明大多数fuzz出来的漏洞对下游内核没有影响。

**复现失败原因分析**：

- （1）漏洞代码存在，但是未被编译到下游内核中（41/62），不可能触发。
- （2）代码上下文改变，这是个例（1/62）。
- （3）环境要求不满足（20/62）。
  - R1——发行版缺少`/dev/raw-gadget`调试设备（syzbot编译该接口是为了从伪USB设备获得模拟输入，以fuzz USB功能）；
  - R2——来自守护进程的背景噪声，例如，占用了loop设备资源，或者导致条件竞争失败；
  - R3——未加载必要的内核模块。

- （4）R4——需要root权限。主要检查uid/gid，还有capability检查（例如，具备`CAP_NET_ADMIN`权限的进程才能使用 raw sockets）。

## 4. SyzBridge

SyzBridge的输入是上游PoC，自动评估其能否在下游内核中触发，并分别解决导致触发失败的4个原因（R1-R4）。`4-1` ~ `4-3` 属于环境调整，`4-4` / `4-5` 属于权限调整。

**4-1. 解决R1**

由于缺乏必要的准备步骤，可能导致PoC触发失败。

**下游内核准备步骤精简策略**：迭代禁用现有的准备步骤，找到能触发漏洞的最精简步骤，避免遗漏必要的准备步骤。

**4-2. 解决R2-背景噪声**

背景噪声通常来自守护进程和服务。对于资源占用问题，解决方法是强制让内核释放loop设备（umount）；对于影响条件竞争问题，可以增加PoC的进程数，或在循环中跑，增大赢得竞争的机率。

**4-3. 解决R3-模块缺失**

**定位显式依赖的缺失模块**：显式指的是模块代码出现在trace中。利用ftrace收集PoC分别在上游和下游内核中执行的函数级trace，识别出函数对应的内核模块。

**定位隐式依赖的缺失模块**：隐式指的是代码未出现在trace中，但会影响漏洞触发。例如Figure 3，trace中访问了`net_device`全局链表，但由另一模块调用`register_netdevice()`来将网络设备注册到该链表。方法是参考[42]来识别隐式依赖，本质是识别出某些全局变量，在某个模块中被读取，在另一个模块被写入。

**模块最简化**：确定能触发漏洞的最少模块，方法类似[syscall minimization](https://github.com/google/syzkaller/blob/master/prog/minimization.go)，一个个添加模块，直到满足需求。

**4-4. 解决R3-非root加载模块**

**问题**：使用`modprobe`命令加载模块，底层会调用`init_module()`，检查用户初始的命名空间`init_user_ns`是否具有`CAP_SYS_MODULE`权限，只有root用户才具备该权限。

**解决**：内核中有一种机制，非root用户可通过某些调用（eg, `socket()`）来自动加载某些模块，例如，调用`syscall(__NR_socket, 16, 3, 6)`就会加载`xfrm_user`模块。本质是调用`request_module()`来加载模块不需要特权，作者通过基于syzkaller的引导型fuzzer来探索能够到达`request_module()`的测试用例（具体思路，通过MLTA[54]静态分析搜索可能到达`request_module()`的syscall，限制fuzz目标，将覆盖率反馈更改为，插桩`request_module()`查看是否加载了新的模块名）。

**结果**：分别识别出316-Ubuntu、236-Fedora、299-Debian、311-Suse个模块，不需要特权即可加载，并且fuzzer生成了相应的测试用例。

**4-5. 内核安全检查**

将`kernel.unprivileged_userns_clone`设置为1启用namespace，利用用户命名空间来绕过内核权限检查，例如`ns_capable(net->user_ns, CAP_NET_ADMIN)`。注意，如果是检查的调用者的权限，`ns_capable(&init_user_ns, cap)`，则无法绕过。

## 5. 实验

**评估上游PoC调整情况**：对230个来自syzbot的漏洞进行测试，看SyzBridge能否提高在下游内核中的复现率，结果见Table IV。root权限中漏洞触发率提高61%，非root权限下漏洞触发率提高1300%。 

![2-result-1](/images/posts/SyzBridge/2-result-1.png)

