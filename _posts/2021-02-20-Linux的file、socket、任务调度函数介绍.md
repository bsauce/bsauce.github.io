---
layout: post
title: Linux的file、socket、任务调度函数介绍
categories: [Kernel-exploit]
description: Linux的file、socket、任务调度函数介绍
keywords: CVE, Kernel, Exploit
---

# Linux的file、socket、任务调度函数介绍

**说明**：调试 CVE-2017-11176 之前需要先学习本文，以对Linux相关知识有个了解。调试分析可参读[【kernel exploit】CVE-2017-11176 竞态Double-Free漏洞调试](https://www.jianshu.com/p/76041ec5c59f)

---

## 一、文件file与socket介绍

#### 1. 文件描述符-fd、文件对象-`struct file`、文件描述表-fdtable（映射fd和file结构体） 及其关系

在Linux中，**“一切都是文件”**，有七种文件：常规、目录、链接、字设备、块设备、fifo和socket，它们都用文件描述符来表示。**三者的关系是，1个文件描述符对应1个file结构，文件描述表-fdtable用来存储这种对应关系**。

- 文件描述符-`fd`：本质上是一个整数，只有对特定的进程才有意义。每个文件描述符与`struct file`相关联。

- 文件对象-`struct file`：用来表示一个被打开的文件，保存文件相关的信息（eg，当前读取的位置），它并不需要匹配磁盘上的某个映像。指向file结构体的指针通常被命名为filp(file pointer)。几个最重要的file结构体成员：

```c
// [include/linux/fs.h]

struct file {
    loff_t                            f_pos;            // "cursor" while reading file
    atomic_long_t                     f_count;          // object's reference counter
    const struct file_operations      *f_op;            // virtual function table (VFT) pointer
  void                              *private_data;      // used by file "specialization"  存放socket指针
  // ...
};
```

- 文件描述表-`fdtable`：文件描述符和file结构体指针的映射表被称作`file descriptor table(fdt)`，它并不是1对1映射，可能存在多个描述符映射到同一结构体指针的情况，因此file结构体中有`f_count`成员来记录引用情况（例如，采用`dup()`系统调用，使两个文件描述符指向相同的file结构，本漏洞中会用到这一点）。FDT的结构体被称为`fdtable`，它就是一个array。

```c
// [include/linux/fdtable.h]

struct fdtable {
    unsigned int max_fds;
    struct file ** fd;      /* current fd array */
  // ...
};
```

进程和`fdtable`的关系：将FDT和进程相连接的是`files_struct`结构体，指向`files_struct`的指针保存在`task_struct`中。由于`fdtable`还包含其他信息，因此并不直接放入`task_struct`中。`files_struct`同样可以在多个线程之间共享。

```c
// [include/linux/fdtable.h]
struct files_struct {
    atomic_t count;           // reference counter
    struct fdtable *fdt;      // pointer to the file descriptor table   !!!
  // ...
};

// [include/linux/sched.h]
// 进程描述符——task_struct, 通过`current`宏可以获取当前正在运行的`task`的结构体指针。
struct task_struct {
    volatile long state;            // process state (running, stopped, ...)
    void *stack;                    // task's stack pointer
    int prio;                       // process priority
    struct mm_struct *mm;           // memory address space
    struct files_struct *files;     // open file information   !!! 用来存进程的文件描述表 - struct fdtable
    const struct cred *cred;        // credentials
  // ...
};
```

**虚函数表VFT**：最常见的VFT是`struct file_operations`。为什么要用到虚函数表？ 由于Linux所有东西都看作文件，但文件类型不同，处理方式也不同，所以有不一样的`file operations`，方便调用。

```c
// [include/linux/fs.h]
struct file_operations {
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    int (*open) (struct inode *, struct file *);
    int (*release) (struct inode *, struct file *);
  // ...
};

// 文件处理调用示例： f_op —— file_operations
if (file->f_op->read)
    ret = file->f_op->read(file, buf, count, pos);
```

#### 2. file、socket、sock的关系——socket粘合file+sock

**`socket`结构体**：`socket`结构体位于网络栈的顶层。创建socket时也会生成1个`struct file`，其`f_op`指针被设置为`socket_file_ops`，对文件的syscall操作最终将调用socket的文件操作。

```c
// [net/socket.c]
static const struct file_operations socket_file_ops = {
    .read = sock_aio_read,      // <---- calls sock->ops->recvmsg()
    .write =    sock_aio_write, // <---- calls sock->ops->sendmsg()
    .llseek =   no_llseek,      // <---- returns an error
  // ...
}
// [include/linux/net.h]				// socket 粘合  file + sock
struct socket {
    struct file     *file;
    struct sock     *sk;				// !!!
    const struct proto_ops  *ops;		// !!!!
  // ...
};
```

**`proto_ops`结构体**：由于`socket`结构体实际上应用了`BSD socket API`（原名为[`Berkeley Socket`](https://blog.csdn.net/blueman2012/article/details/6693605)，允许不同主机或者同一个计算机上的不同进程之间的通信），它集成了一个特殊的VFT结构体`proto_ops`。不同类型的`socket`（例如AF_INET、AF_NETLINK等）实现它自己的`proto_ops`。

```c
// [include/linux/net.h]
struct proto_ops {
    int     (*bind)    (struct socket *sock, struct sockaddr *myaddr, int sockaddr_len); 	// 给套接字分配一个地址。当使用 socket()创造一个套接字时, 只是给定了协议族,并没有分配地址。
    int     (*connect) (struct socket *sock, struct sockaddr *vaddr,  int sockaddr_len, int flags); // 为一个套接字设置连接，参数有文件描述符和主机地址。
    int     (*accept)  (struct socket *sock, struct socket *newsock, int flags);	// 当应用程序监听来自其他主机的面对数据流的连接时，通过事件（比如Unix select()系统调用）通知它。
  // ...
}
```

内核处理BSD系统调用的过程：

1. 从FDT中检索`file`结构体
2. 从`file`结构体中检索`socket`结构体
3. 调用`proto_ops`中的操作

**`sock`结构体**：因为一些协议的操作可能需要进入到网络栈的底层，所以`socket`结构体有一个指针指向`sock`对象，该指针是为了进行`socket`的协议操作(`proto_ops`)。**`sock`结构体是底层（网卡驱动）和高层（`socket`）的中间层，能以通用的方式保持接收和发送的缓冲区**。`socket`结构体连接`file`结构体和`sock`结构体，**三者的关系——`struct file` <=> `struct socket` <=> `struct sock`**，三者都双向引用，便于数据在网格栈中上下移动。**struct sock对象通常称为sk，而struct socket对象通常称为sock。**

```c
// [include/linux/sock.h]
struct sock {
    int         sk_rcvbuf;    // theorical "max" size of the receive buffer
    int         sk_sndbuf;    // theorical "max" size of the send buffer
    atomic_t        sk_rmem_alloc;  // "current" size of the receive buffer
    atomic_t        sk_wmem_alloc;  // "current" size of the send buffer
    struct sk_buff_head sk_receive_queue;   // head of doubly-linked list		// !!!!!!!! sk_buf缓冲区
    struct sk_buff_head sk_write_queue;     // head of doubly-linked list
    struct socket       *sk_socket;
  // ...
}
```

**SKB缓冲区**：当通过网卡接收到数据包时，驱动将网络数据包排队到sock的接收缓冲区中，数据包会在缓冲区一直存在直到程序决定接收它（使用`recvmsg()`系统调用）。发送时也一样（`sendmsg()`），只不过由网卡将数据包从队列移出并发送。这些网络数据包就是`struct sk_buff`，也称为SKB，这些缓冲区基本上都是skb的双向链表。

#### 3. Netlink Socket（socket的一种）

**`Netlink Socket`**：是socket的一种类型，由于`struct sock`和`struct socket`结构体是支持各种套接字的通用数据结构，因此有必要在某种程度上进行专门化，其`proto_ops`指针（BSD API）对应的是`netlink_ops`，如下所示。**`netlink_sock`是具有一些附加属性的`sock`。**`Netlink Socket`（`AF_NETLINK`）允许内核和用户态之间的通信，它可以用来修改路由表、接收SELinux事件通知，甚至与其他用户进程通信。

```c
// [net/netlink/af_netlink.c]
static const struct proto_ops netlink_ops = {
    .bind =     netlink_bind,
    .accept =   sock_no_accept,     // <--- calling accept() on netlink sockets leads to EOPNOTSUPP error
    .sendmsg =  netlink_sendmsg,
    .recvmsg =  netlink_recvmsg,
  // ...
}
// [include/net/netlink_sock.h]
struct netlink_sock {
    /* struct sock has to be the first member of netlink_sock */
    struct sock     sk;
    u32         pid;
    u32         dst_pid;
    u32         dst_group;
  // ...
};
```

注释：sk是`netlink_sock`的第1个成员。好处一，它允许内核在不知道其精确类型的情况下操作通用`sock`结构体。 好处二，`＆netlink_sock.sk`是`＆netlink_sock`同个地址，所以释放指针`＆netlink_sock.sk`实际上释放了整个`netlink_sock`对象。

#### 4. 总体关系图

通过current指针找到`struct tast_struct` **=>** `struct file_struct` (存fdt) **=>** `struct fdtable` (映射fd和file结构) **=>** `struct file` (存`file_operations`文件操作 + `socket`) **<=>** `struct socket` (存放 `struct proto_ops` socket操作 + `struct sock`) **<=> ** `struct sock` **=>** `sk_buf` 。

![1](\images\posts\CVE-2017-11176\1.png)

#### 5. 引用计数

引用计数：内核的一种机制。为了减少内核内存泄漏和防止UAF，大多数Linux的数据结构中有`ref counter`，为`atomic_t`类型（`int`）。通过如下原子操作对`ref counter`进行操作：

- atomic_inc()
- atomic_add()
- atomic_dec_and_test()  // 减去1并测试它是否等于零

漏洞：这些操作都要由开发人员手动调用来完成。当一个对象被另一个对象引用时，增加其refcounter；删除此引用时，减少refcounter。当refcounter为零时，通常会释放该对象。如果处理不当导致不平衡，会引发以下漏洞。

- `refcounter`减少两次：UAF。
- `refcounter`增加两次：内存泄漏或整数溢出导致UAF。

Linux内核有专门的函数来处理具有通用接口的`refcounter`（如`kref`,`kobject`），但没有得到系统的使用。通常来说，struct对象有自己的`refcounter`处理函数，`*_get()`类函数负责引用，`*_put()`类函数负责释放（不能完全根据名字来判断功能，还需要看代码，例如`skb_put()`不减少任何`refcounter`）。示例如下：

- **`struct sock`**： `sock_hold()`, `sock_put()`
- **`struct file`**： `fget()`, `fput()`
- **`struct files_struct`**： `get_files_struct()`, `put_files_struct()`

---

## 二、任务状态、阻塞与唤醒

#### 1. 任务状态

**[任务状态](https://www.mywiki.cn/Hovercool/index.php/linux%e8%bf%9b%e7%a8%8b%e7%8a%b6%e6%80%81)**：任务状态由`task_struct`中的state字段表示，主要有两种状态如下，其他任务状态见`include/linux/sched.h`。

- **Running**：进程**正在运行**或已经**准备就绪**只等待在cpu上运行。如`TASK_RUNNING`—可执行状态，运行队列。
- **Waiting**：进程正在等待某种事件/资源。如`TASK_INTERRUPTIBLE`—可中断的睡眠状态，等待队列。

设置state状态：可以直接修改state字段，也可以通过`__set_current_state()`来设置state字段。

```c
// [include/linux/sched.h]
#define __set_current_state(state_value)            \
    do { current->state = (state_value); } while (0)
```

####  2. 运行队列

运行队列—`struct rq`：每个CPU都有自己的运行队列（允许真正的多任务处理）。运行队列具有一个任务（由调度器选择在指定的CPU上运行）列表。还具有统计信息，使调度器做出“公平”选择并最终重新平衡每个cpu之间的负载（即cpu迁移）。`deactivate_task()`函数将任务从运行队列中移出，`activate_task()`将任务加入到运行队列中。

```c
// [kernel/sched.c]
struct rq {
  unsigned long nr_running;   // <----- statistics
  u64 nr_switches;            // <----- statistics
  struct task_struct *curr;   // <----- the current running task on the cpu     CPU当前运行的任务
  // ...
};
```

阻塞任务：将任务从正在运行状态切换到等待状态。通过如下代码阻塞任务，直到被唤醒。

- 将任务的运行状态设置为`TASK_INTERRUPTIBLE`。
- 调用`deactivate_task()`以移出运行队列，但不会直接调用`deactivate_task()`，通常调用`schedule()`来调度。

```c
void make_it_block(void)
{
  __set_current_state(TASK_INTERRUPTIBLE);
  schedule();
}
```

调度函数-`schedule()`：选择下一个在CPU上运行的任务，更新运行队列的curr字段。如果调用`schedule()`时当前任务状态不是`TASK_RUNNING`（state字段不为0），并且没有信号挂起，则会调用`deactivate_task()`。

```c
asmlinkage void __sched schedule(void)
      {
        struct task_struct *prev, *next;
        unsigned long *switch_count;
        struct rq *rq;
        int cpu;

          // ... cut ...

        prev = rq->curr;    // <---- "prev" is the task running on the current CPU

        if (prev->state && !(preempt_count() & PREEMPT_ACTIVE)) {   // <----- ignore the "preempt" stuff
          if (unlikely(signal_pending_state(prev->state, prev)))
            prev->state = TASK_RUNNING;
          else
            deactivate_task(rq, prev, DEQUEUE_SLEEP);     // <----- task is moved out of run queue
          switch_count = &prev->nvcsw;
        }

        // ... cut (choose the next task) ...
      }
```

#### 3.等待队列

等待队列：由当前阻塞（等待）的任务组成的双链表——`wait_queue_head_t`。任务等待资源或特殊事件，例如，服务端server等待即将到来的连接，除非被标记为“非阻塞”，否则`accept()`系统调用将阻塞主线程，直到其他东西唤醒它。

```c
// [include/linux/wait.h]
typedef struct __wait_queue_head wait_queue_head_t;

struct __wait_queue_head {
    spinlock_t lock;
    struct list_head task_list;			// `struct list_head`是Linux实现双链表的方式
};
```

`wait_queue_t`：等待队列的每个元素都具有`wait_queue_t`。

```c
// [include/linux.wait.h]

typedef struct __wait_queue wait_queue_t;
typedef int (*wait_queue_func_t)(wait_queue_t *wait, unsigned mode, int flags, void *key);

struct __wait_queue {
    unsigned int flags;
    void *private;                
    wait_queue_func_t func;     // <----- we will get back to this
    struct list_head task_list;
};
```

创建等待队列的元素：通过`DECLARE_WAITQUEUE()`宏创建一个等待队列元素。

```c
// [include/linux/wait.h]

#define __WAITQUEUE_INITIALIZER(name, tsk) {                \
    .private    = tsk,                      \
    .func       = default_wake_function,            \   // !!!!! 注意，将func设置为 default_wake_function()
    .task_list  = { NULL, NULL } }

#define DECLARE_WAITQUEUE(name, tsk)                    \
    wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk) // <----- it creates a variable!

DECLARE_WAITQUEUE(my_wait_queue_elt, current); // <----- use the "current" macro   !!!调用方法
```

加入等待队列：一旦声明了一个等待队列元素，就可以调用`add_wait_queue()`函数将其加入到等待队列中。通过加锁并将元素加到双向链表中。

```c
// [kernel/wait.c]
void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
    unsigned long flags;

    wait->flags &= ~WQ_FLAG_EXCLUSIVE;
    spin_lock_irqsave(&q->lock, flags);
    __add_wait_queue(q, wait);              // <----- here
    spin_unlock_irqrestore(&q->lock, flags);
}
static inline void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
    list_add(&new->task_list, &head->task_list);
}
```

#### 4. 唤醒任务

唤醒任务：为了在资源可用时被唤醒，它必须将自己注册到该资源的等待队列（通过`add_wait_queue()`调用）。通过`__wake_up()`函数唤醒任务，实际调用`__wake_up_common()`函数，遍历等待队列中的每个元素（`list_for_each_entry_safe()`是与双链表一起使用的宏），对每个元素都调用`func()`回调函数。`func`在`DECLARE_WAITQUEUE()`宏中被初始化为`default_wake_function()`，`default_wake_function()`将等待队列元素的**private**字段（在大多数情况下指向睡眠任务的`task_struct`）作为参数调用`try_to_wake_up()`。

```c
// [kernel/sched.c]
/**
 * __wake_up - wake up threads blocked on a waitqueue.
 * @q: the waitqueue
 * @mode: which threads
 * @nr_exclusive: how many wake-one or wake-many threads to wake up
 * @key: is directly passed to the wakeup function
 *
 * It may be assumed that this function implies a write memory barrier before
 * changing the task state if and only if any tasks are woken up.
 */
void __wake_up(wait_queue_head_t *q, unsigned int mode,
            int nr_exclusive, void *key)
{
    unsigned long flags;

    spin_lock_irqsave(&q->lock, flags);
    __wake_up_common(q, mode, nr_exclusive, 0, key);    // <----- here
    spin_unlock_irqrestore(&q->lock, flags);
}

// [kernel/sched.c]
    static void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
          int nr_exclusive, int wake_flags, void *key)
    {
      wait_queue_t *curr, *next;

[0]   list_for_each_entry_safe(curr, next, &q->task_list, task_list) { // 遍历等待队列中的每个元素（list_for_each_entry_safe()是与双链表一起使用的宏），对每个元素都调用func()回调函数。
        unsigned flags = curr->flags;

[1]     if (curr->func(curr, mode, wake_flags, key) &&
            (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
          break;
      }
    }

// 注意：通常很少直接调用__wake_up()，而是调用这些辅助宏。
// [include/linux/wait.h]
#define wake_up(x)          __wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_nr(x, nr)       __wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_all(x)          __wake_up(x, TASK_NORMAL, 0, NULL)

#define wake_up_interruptible(x)    __wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_nr(x, nr) __wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_all(x)    __wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
```

`try_to_wake_up()`将任务加入运行队列中并更改其状态为`"TASK_RUNNING"`，使其可调度。再由`schedule()`进行调度，回到中断的地方继续执行。

```c
int default_wake_function(wait_queue_t *curr, unsigned mode, int wake_flags,
              void *key)
{
    return try_to_wake_up(curr->private, mode, wake_flags);
}

static int try_to_wake_up(struct task_struct *p, unsigned int state,
              int wake_flags)
{
    struct rq *rq;

    // ... cut (find the appropriate run queue) ...

out_activate:
    schedstat_inc(p, se.nr_wakeups);              // <----- update some stats
    if (wake_flags & WF_SYNC)
        schedstat_inc(p, se.nr_wakeups_sync);
    if (orig_cpu != cpu)
        schedstat_inc(p, se.nr_wakeups_migrate);
    if (cpu == this_cpu)
        schedstat_inc(p, se.nr_wakeups_local);
    else
        schedstat_inc(p, se.nr_wakeups_remote);
    activate_task(rq, p, en_flags);               // <----- 放入运行队列
    success = 1;

    p->state = TASK_RUNNING;                      // <----- 将任务状态修改为TASK_RUNNING

    // ... cut ...
}
```

例子：线程A运行`task_0_wants_resource_a()`函数，因资源不可用而阻塞。一段时间后，资源所有者（线程B）使资源可用并调用`task_1_makes_resource_available()`，之后`task_0_wants_resource_a()`可以恢复执行。这是Linux内核代码的常见模式，资源是一个泛指，可以是等待某个事件，某个条件为真的东西。

```c
struct resource_a {
  bool resource_is_ready;
  wait_queue_head_t wq;
};

void task_0_wants_resource_a(struct resource_a *res)
{
  if (!res->resource_is_ready) {
    // "register" to be woken up
    DECLARE_WAITQUEUE(task0_wait_element, current);
    add_wait_queue(&res->wq, &task0_wait_element);

    // start sleeping
    __set_current_state(TASK_INTERRUPTIBLE);
    schedule();

    // We'll restart HERE once woken up
    // Remember to "unregister" from wait queue
  }

  // XXX: ... do something with the resource ...
}

void task_1_makes_resource_available(struct resource_a *res)
{
  res->resource_is_ready = true;
  wake_up_interruptible_all(&res->wq);  // <--- unblock "task 0"
}
```

---

## 三、Linux内核中的双链表

Linux内核驱动开发会经常用到Linux内核中经典的双向链表**list_head**，以及它的拓展接口和宏定义：`list_add`、`list_add_tail`、`list_del`、`list_for_each_entry`等。

```c
struct list_head {
    struct list_head *next, *prev;
};
```

开始创建一个链表头**head_task**，并使用`LIST_HEAD(head_task)`进行初始化；创建完成后，然后创建第一个节点，再通过使用`list_add`接口将这个**first_task**节点插入到**head_task**之后；每次插入一个新的节点，都是紧靠着**head_task**节点的，先来的节点靠后，而后来的节点靠前，也就是**先进后出，后进先出**，类似于栈。

---

## 参考：

ADLab——[Linux内核CVE-2017-11176漏洞分析与复现](https://www.freebuf.com/vuls/196673.html)

Kaka——[cve-2017-11176 利用分析+exp](https://xz.aliyun.com/t/5358)

[CVE-2017-11176: A step-by-step Linux Kernel exploitation](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html) —— [翻译1](https://xz.aliyun.com/t/5185) [翻译2](https://xz.aliyun.com/t/5319) [翻译3](https://blog.csdn.net/weixin_42177005/article/details/104002923) [翻译4](https://blog.csdn.net/weixin_42177005/article/details/104234951)

https://www.cvedetails.com/cve/CVE-2017-11176/