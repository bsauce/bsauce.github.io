---
layout: post
title: 【bsauce读论文】2023-CCS-Syzdirect-内核导向型模糊测试
categories: Paper
description: 本文提出SyzDirect，主要工作是识别入口syscall、参数优化、根据路径反馈来指导种子调度。对syzdirect进行漏洞复现和补丁测试，发现比其他内核fuzzer，漏洞复现提高320%，补丁测试提高25.6%。
keywords: Kernel fuzz, Paper
---

# 【bsauce读论文】2023-CCS-Syzdirect-内核导向型模糊测试

## 基本信息

- 原文标题：SyzDirect: Directed Greybox Fuzzing for Linux Kernel
- 原文作者：Xin Tan，Yuan Zhang，Jiadong Lu，Xin Xiong，Zhuang Liu，Min Yang
- 作者单位：Fudan University
- 关键词：DGF
- 原文链接：[DOI link](https://doi.org/10.1145/3576915.3623146)
- 开源代码：[Syzdirect]([GitHub - seclab-fudan/SyzDirect](https://github.com/seclab-fudan/SyzDirect))

## 1. 论文要点

**问题**：给定内核程序点，如何识别正确的入口syscall、确定参数范围并引导syzkaller到达指定点。

**主要内容**：提出SyzDirect，主要工作是识别入口syscall、参数优化、根据路径反馈来指导种子调度。对syzdirect进行漏洞复现和补丁测试，发现比其他内核fuzzer，漏洞复现提高320%，补丁测试提高25.6%。

## 2. 介绍

**内核DGF挑战**：

- （1）映射内核代码与syscall变体（控制流）：内核有330个原始syscall，Syzkaller定义了4200个syscall变体，识别正确的入口syscall有助于减少耗时。且内核中使用了大量的间接调用，控制流分析很容易产生误报。
  - 案例：见Figure 1，sendmsg只有使用RDS（Reliable Datagram Socket）协议才能到达；间接调用使得控制流分析也不准确，`sendmsg→...→rds_sendmsg→...→rds_rdma_extra_size`，基于类型的指针分析[31]不能很好的解决本问题，识别出235个调用能到达本位置。
- （2）准备syscall参数（数据流）：需要分析深层代码，但内核代码有大量间接调用、链表操作、嵌套的数据结构和多层指针引用，很难进行准确的数据流分析（precondition分析）。
  - 案例：sendmsg的第2个参数需满足条件，才能走到`rds_rdma_extra_size()`调用点（Line 6）。

![Fig-1-sendmsg-example](/images/posts/Syzdirect/Fig-1-sendmsg-example.png)

**Syzdirect流程**：给定内核代码位置，采用静态分析对内核代码和Syzlang进行分析。

- 一是对内核操作和resource建模，为内核代码匹配入口syscall变体（Syzlang模板中）；
- 二是识别syscall依赖，也即生成resource的syscall；
- 三是识别出到达指定点，syscall参数需满足的条件，优化入口syscall的参数描述。
- 利用以上信息引导fuzz，主要是定制化种子变异策略和路径反馈机制。

## 3. Approach

概念：

- 入口syscall：表示原始syscall，Linux内核中有300多个调用。
- syscall变体：syzlang中定义的具体调用，一个原始入口syscall可以有多个syscall变体，代表一种功能。

### 3-1. 入口syscall识别

**思路**：由于Linux内核对file/socket/device等抽象资源进行管理，syscall是对resource进行操作的接口，内核函数实现负责具体操作。所以**可根据所操作的resource来识别入口syscall**。

**示例**：见Fig 1，目标函数`rds_rdma_extra_size()`只能通过内核函数`rds_sendmsg()`可达，`rds_sendmsg()`是`rds_proto_ops`结构的成员函数。本文模型可以识别出`rds_create()`函数用到了`rds_proto_ops`结构（该函数注册socket时需指定`AF_RDS` family中的`SOCK_SEQPACKET` type），然后发现只有`$rds` family（`socket$rds, bind$rds,sendmsg$rds`）提供了到该resource的接口，这样就能将目标函数匹配到相应的syscall变体，也即`rds_rdma_extra_size()`通过`sendmsg$rds`可达。

**步骤**：

- dispatch过程：内核解析参数，跳转到对应功能函数。也即确定操作什么resource，如何操作。

- anchor函数：dispatch过程之后执行的第1个函数。

- （1）操作建模：根据syscall名和命令参数来表示对resource的操作类型。对于Syzlang，可直接提取出syscall名和命令参数（将常数当作命令参数）。对于内核源码，采用控制流和数据流分析来收集命令值（首先，用后向控制流分析，从syscall入口往后分析CFG，定位switch语句；再进行数据流分析，确定switch变量是否和syscall参数有关），将case分支中的函数当作anchor函数，case对应的常数作为命令参数。

  - 示例：Fig 3，syscall变体`keyctl$update`采用`KEYCTL_UPDATE`作为命令值，操作建模记为`[keyctl, KEYCTL_UPDATE]`；代码方面，每个case分支中的函数作为anchor函数，收集case中的常量作为操作，提取`KEYCTL_UPDATE`常量（Line 6）和anchor函数`keyctl_update_key()`（Line 7）作为` [keyctl, KEYCTL_UPDATE]`。

    ![Fig-3-operation-modeling](/images/posts/Syzdirect/Fig-3-operation-modeling.png)

- （2）resource建模：resource命名在syzlang和内核代码中可能不一致。

  - （2-1）Syzlang模板。可采用创建resource时用到的字符串+常量来表示resource，eg，创建文件系统/设备resource时需要一个字符串（文件系统/设备路径），创建socket时需指定family和socket类型。

  - 示例：Fig 4，`sendmsg$rds`需要resource `sock_rds`作为输入（Line 2），创建`sock_rds`用到的常量可表示该resource - `[AF_RDS,SOCK_SEQPACKET]`；同理，`openat$i915`（去掉路径前缀）可描述resource `fd_i915`。

    ![Fig-4-resource-modeling](/images/posts/Syzdirect/Fig-4-resource-modeling.png)

  - （2-2）内核函数。有时，通过间接调用才能执行到目标点，可向上找到间接调用所在的**虚表结构**。

    - 首先，手动收集总结内核中的**注册函数**（例如`sock_register()`），找到其调用点，如`rds_init()`处，分析调用参数（`rds_family_ops`结构），找到**创建函数**（`rds_create()`）；
    - 然后，分析**创建函数**中的赋值语句，找到resource相关的常量和**虚表结构**（`rds_proto_ops`）；
    - 最后，对每个**注册函数**的调用点，采用收集到的resource相关的常量来寻找对应的resource。

  - 示例：

    - 可参见Fig 1，`rds_rdma_extra_size()`往上控制流分析找到`rds_sendmsg()`函数，再往上涉及间接调用，所以将`rds_sendmsg()`看作anchor函数；
    - 检查`rds_sendmsg()`的引用点，发现属于`rds_proto_ops`结构（属于RDS socket的虚表）；
    - 接下来分析RDS socket创建，见Fig 5。
    - Line 4 - RDS模块初始化调用socket注册函数；
    - Line 9-10 - 分析其参数和嵌套成员，找到family类型和创建函数`rds_create()`；
    - Line 22 - 找到`rds_proto_ops`赋值位置；Line 16 - 找到socket类型为`SOCK_SEQPACKET`。即可确认`rds_sendmsg()` anchor函数需要`AF_RDS SOCK_SEQPACKET` resource。

  - ![Fig-5-resource-moduling-example](/images/posts/Syzdirect/Fig-5-resource-moduling-example.png)

- （3）基于anchor函数匹配syscall变体：从目标点反向控制流分析，找到所有路径上的anchor函数，建模，然后和syscall变体（Syzlang）比对，看是否有相同操作和resource模型。
- （4）识别入口syscall：最终识别入口syscall和syscall变体。

### 3-2. syscall依赖推断

**思路**：根据所操作的resource来推断，例如，`socket$rds`和`sendmsg$rds `对同一socket进行操作。参考Healer[40]的方法，分析入口syscall的输入参数，收集参数的resource类型，再找到能生成该resource类型的相关syscall，如果找到过多相关syscall，可只保留本模块中的。

### 3-3. syscall参数优化

**思路**：参考syzlang模板。仅仅依靠syscall变体是无法准确确定参数范围的，eg，Fig 1中Line 6检查消息类型是否为`RDS_CMSG_RDMA_ARGS`，这是syscall变体无法确定的。Syzlang中根据resource（eg，a socket）或sub-resource（eg，a socket for a specific protocol）对syscall参数进行了描述。例如，`sendmsg$rds`支持7种消息类型（RDS_CMSG_RDMA_ARGS, RDS_CMSG_RDMA_DEST, RDS_CMSG_RDMA_MAP, etc）。可先识别出支配目标位置或影响间接调用的条件（**代码条件**，常量），再匹配到syzlang中的**参数条件**，这样不需要进行数据流分析和precondition分析，以进行优化约束剪枝。

**示例**：见Fig 1，Line 6的条件涉及值`RDS_CMSG_RDMA_ARGS`，对应到syzlang中的参数条件，也即`RDS_CMSG_RDMA_ARGS`消息类型。

见Fig 6，Syzlang模板中，`sendmsg$rds`第2个参数是`msghrd_rds`对象，其包含一个嵌套结构`cmsghrd_rds`，`cmsghrd_rds`是一个union，可以是7个控制消息中的一个（`RDS_CMSG_RDMA_ARGS`，`RDS_CMSG_RDMA_DEST`，etc.）。根据先前识别的参数条件-`RDS_CMSG_RDMA_ARGS`，正好匹配Fig 6中Line 10的参数描述，可删除其他消息类型，以优化参数。

![Fig-6-Argument-refinement-example](/images/posts/Syzdirect/Fig-6-Argument-refinement-example.png)

### 3-4. 导向型内核fuzz

**思路**：根据以上信息，限制种子变异过程，生成符合模板的测试用例，优先变异距离目标近的种子并赋予更多能量。保存测试用例时，优先考虑能覆盖新的代码边，或距离目标近的种子。

**距离计算**：距离计算参考AFLGo。

- Syscall距离：所有基本块中到目标点最短的距离；
- seed距离：取seed中最短的syscall距离；
- template距离：选最短的5个seed距离的平均值。

**方法**：

- 模板引导变异：模板就是前面的Syscall入口和优化后的参数。
- 距离引导调度：基于距离反馈优化种子调度。

## 4. 实验

**实验内容**：漏洞复现与补丁测试

**对比**：syzkaller、SyzGo（AFLGo变体）、GREBE。

**结果**：漏洞复现个数，比syzkaller、SyzGo和GREBE分别多320%，281%，121%；补丁测试覆盖目标数，比syzkaller、SyzGo分别多覆盖25.6%，36.1%。

![Table-1-bug-reproducing](/images/posts/Syzdirect/Table-1-bug-reproducing.png)

![Table-3-patch-testing](/images/posts/Syzdirect/Table-3-patch-testing.png)







