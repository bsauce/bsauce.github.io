---
layout: post
title: 【bsauce读论文】2023-S&P-内核Use-After-Cleanup漏洞挖掘与利用
categories: Paper
description: 【bsauce读论文】2023-S&P-内核Use-After-Cleanup漏洞挖掘与利用
keywords: Kernel fuzz, Paper
---

# 【bsauce读论文】2023-S&P-内核Use-After-Cleanup漏洞挖掘与利用

本文参考[G.O.S.S.I.P 阅读推荐 2023-01-06 UACatcher](https://mp.weixin.qq.com/s/7usXokjDSNeFyWcPu7zSYA)做一些补充。

## 1. UAC漏洞介绍

**UAC漏洞介绍**：Use-After-Cleanup （UAC）漏洞类似UAF，本文主要检测Linux内核中UAC漏洞。UAC基本原理参见图Fig-1。首先，UAC漏洞和系统中特定的设备（device）的卸载（例如一个USB设备被用户拔出）相关，当一个特定的设备释放后，原来和这个设备相关的内存对象应该就不再有效了。然而，如果攻击者能抓住特定的时间窗口（race window），在设备释放前就开始启动相关内存对象访问，并能让这个操作“慢一点”，在设备释放后（相关内存对象也不再有效)再执行内存访问，就会产生和UAF漏洞攻击类似的效果。（根本原因是，**内核没有正确实现同步机制，所以syscall路径没有意识到对象已经被释放，这是一种特殊的并发UAF漏洞**）

![Fig1-UAC-Root-Cause](/images/posts/UACatcher/Fig1-UAC-Root-Cause.png)

注意到设备的卸载是从硬件层自底向上通知直至用户层，而用户态代码对设备资源的访问则需要透过syscall从上往下访问（这种访问模型见下图）。这两类（并发）事件如果撞到一起，就很容易产生concurrency bug，从而导致UAC相关问题的发生。

![Fig3-UAC-Layer-Model](/images/posts/UACatcher/Fig3-UAC-Layer-Model.png)

### 1-1. 设备移除处理函数示例

![Fig2-Device-Removal-Struct](/images/posts/UACatcher/Fig2-Device-Removal-Struct.png)

**函数指针**：`device_driver->remove`

当设备从主机移除时调用 `*remove` 函数，实际会调用特定设备相关的函数 `*disconnect` （以USB为例），负责清理USB相关的资源。结构包含的关系为 `usb_driver` -> `usbdrv_wrap` -> `device_driver`，所以设备通常会`device_driver` 这样一个基类型，可以通过这个特点来找到目标驱动和 `unreg-entry` 函数。

### 1-2. 分层模型

UAC分层模型（Layered Model）详见Fig-3。

> `deallocation site`：bottom-up cleanup routine 释放内核对象的地方
>
> `dereference site`： top-down syscall routine 使用该内核对象的地方
>
> dPair：针对同一内核对象的一对 `deallocation site` 和 `dereference site`
>
> 层边界函数（layer-boundary functions）：包含 `unreg-entry` 函数（cleanup例程的入口函数）和 `interface` 函数（syscall例程的入口函数）

## 2. UAC漏洞挖掘

### 2-1. 漏洞案例

本文实现了一个名为`UACatcher`的分析工具，用它自动化寻找代码（特别是Linux内核代码）中的UAC问题。下图中就是作者利用`UACatcher`发现的一个真实的UAC bug：

该漏洞在 Linux 2.6.22-rc2 中（于2007年5月引入），在2021年5月才修复，存在了近14年。`hci_unregister_dev()`函数就是HCI顶层的 `unreg-entry` 函数，在利用`hci_sock_dev_event()`通知所有socket来回收目标对象`hdev->workqueue`之后，在3899行调用`destroy_workqueue()`释放目标对象；而 `hci_sock_sendmsg()` （通过调用 `sendmsg` 触发）在1829行会用到该对象。

![Fig4-Example-Bluetooth-UAC](/images/posts/UACatcher/Fig4-Example-Bluetooth-UAC.png)

### 2-2. UACatcher介绍

**`UACatcher`工作机制**：首先，`UACatcher`要借助Linux内核驱动的一些领域知识帮忙，分析和收集那些与设备相关的代码（下图中的Layer Preparing）；然后，`UACatcher`会寻找那些和特定设备相关的内存对象，并确定一个对象的 deallocation site 和 dereference site （作者称其为dPair），而定位这种dPair（下图中的dPairs Locating）对于寻找UAC bug是至关重要的；最后就是利用静态分析算法来确认某个dPair是否会导致UAC行为的发生。这部分工作的细节非常丰富，读者可以在论文的第四章中找到更多的有意思的内容。

![Fig5-UACacher-Overview](/images/posts/UACatcher/Fig5-UACacher-Overview.png)

**UACacher实现**：代码采用Python和CodeQL实现，参见 https://github.com/uacatcher/uacatcher-repo

### 2-3. 真假UAC

![Fig6-True-UAC-False-UAC](/images/posts/UACatcher/Fig6-True-UAC-False-UAC.png)

**真UAC**：见 Fig-6 左边，漏洞对象是 `req_workqueue` ，syscall例程的检查语句 `test_bit(HCI_UP, &hdev->flags)` 位于`hci_req_sync_lock`锁原语外面，所以有可能syscall例程先通过了`test_bit`检查然后等待`hci_req_sync_lock`锁，而cleanup例程正占用该锁进行释放工作，导致UAC。本质原因就是没有对 `hdev->flags` 访问进行正确的锁保护。

**假UAC**：该示例的 `dereference site` 不可能在 `deallocation site` 之后发生，因为对 `ndev->flags` 的读写进行了正确的 `req_lock` 锁保护，在释放时就将 `ndev->flags` 清零了。

因此，在检测UAC漏洞时，要进行正确的 `lock-set` 分析和 ` happen-before` 关系分析。

## 3. 挖掘结果

`UACatcher`在现实中针对Linux 5.11 (git commit 7289e26f395b) 内核版本进行了分析，发现了346个UAC bug，其中有277个得到了社区确认和修复，并拿到了15个CVE。

![Table3-Found-Bugs](/images/posts/UACatcher/Table3-Found-Bugs.png)

### 3-1. 漏洞可利用性

**评估标准**：竞争窗口是否足够大或者是否可控；是否可通过伪终端来利用。

**结果**：在4个模块中找到13个可利用的漏洞，见Fig-10。作者开发了第6个漏洞的提权EXP，具体两次使用了userfaultfd，第一次是使syscall例程暂停，开始cleanup例程，另一个错误处理线程使用 setxattr 来堆喷布置恶意数据。

![Fig10-Exploitable-Bug](/images/posts/UACatcher/Fig10-Exploitable-Bug.png)

## 4. UAC漏洞利用

### 4-1. 竞争窗口识别与评估

识别 `time-consuming` 函数（内存分配/释放、日志记录、IO操作等函数）和 `time-controllable` 函数（内核与用户数据交互，例如 `copy_{from/to}_user`）。

### 4-2. 用户设备模拟

由于UAC漏洞的触发需要系统设备的卸载和释放作为前提，那么对于攻击者来说，这种利用条件是否就很苛刻呢？作者在第五章回答了这类疑问——通过一个真实的用户态可构造的“pseudoterminal device”，攻击者可以在无需真实物理设备且无需高权限的情况下，触发设备的释放（从而可能触发UAC bug）！

![Fig8-Emulate-Bluetooth-Step](/images/posts/UACatcher/Fig8-Emulate-Bluetooth-Step.png)

**伪终端**：` pseudo-terminal`（简称`pty`）是虚拟字符设备端点，一端叫作`master`（通常由网络应用所使用，例如 ssh），另一端叫作`slave`（通常由终端程序所使用，例如 bash）。Linux系统中，用户程序A可以打开`/dev/ptmx` 获得 master 端描述符，内核PTY驱动就会在 `/dev/pts` 目录下分配一个slave端文件，来模拟硬件端设备（支持System V API，~~`/dev/ptyX` 用作master，`/dev/ttyX` 用作slave~~）。

**行规则**：**Line Discipline**，内核TTY驱动负责将数据格式化，便于硬件与用户之间的数据交互。用户可以选取不同的行规则，来规定TTY的数据格式。例如，基于串口的蓝牙控制器，为了根据HCI协议转换来格式化数据，用户需打开并设置HCI行规则，这样该控制器才能被内核识别为 Bluetooth HCI dongle。

**模拟示例**：Fig-8展示了模拟蓝牙设备的示例。

- （1）攻击者打开 `/dev/ptmx` 创建伪终端设备，获得文件描述符f1和f2分别指向master和slave端；
- （2）调用`ioctl(fd2)`来为slave设备注册蓝牙行规则（`N_HCI`），如果不设置的话默认会注册TTY行规则（`N_TTY`）；
- （3）切换行规则之后，在attach到特定蓝牙控制器时，攻击者需处理数据，也即从fd1读取数据请求并将回复数据写入fd1；
- （4）为了触发cleanup例程，只需关闭fd2，PTY驱动就会kill模拟设备，并向行规则层发送信号。

**伪终端和虚拟设备（eg，vhci）的区别**：

- （1）伪终端代码一直在内核中，而虚拟设备需要配置和安装（需要root权限）；
- （2）对虚拟设备的某些操作（例如 open/ioctl）也需要root权限，而伪终端权限较低，例如，蓝牙栈只需`CAP_NET_ADMIN` 权限，Amateur Radio 和 Controller Area Network 在切换行规则时需要 `CAP_NET_ADMIN` 权限，NFC不需要任何权限。

## 参考

[G.O.S.S.I.P 阅读推荐 2023-01-06 UACatcher](https://mp.weixin.qq.com/s/7usXokjDSNeFyWcPu7zSYA)

 <https://github.com/uacatcher/uacatcher-repo>