---
layout: post
title: 【LLVM】如何写一个pass
categories: [程序分析技术]
description: 【LLVM】如何写一个pass
keywords: LLVM, pass, Program analysis
---

## 1.简介

LLVM pass是编译器中很重要的部分，能够对代码进行转化和优化。所有pass都是Pass类的子类，通过覆盖Pass类的虚函数来实现功能，可继承的类有`ModulePass` , `CallGraphSCCPass`, `FunctionPass` , `LoopPass`, `RegionPass`, `BasicBlockPass`。详见<https://llvm.org/doxygen/classllvm_1_1Pass.html>。

环境搭建参考：https://blog.csdn.net/l2563898960/article/details/82871826

本文参考：https://llvm.org/docs/WritingAnLLVMPass.html

## 2.写hello world pass

Hello pass用于打印出内部函数的函数名，不会修改程序，只是监视作用，Hello pass的源码和文件在LLVM源码的`lib/Transforms/Hello`目录下。

#### （1）设置

首先，配置和安装LLVM；然后在LLVM源码目录下创建一个新目录，这里假设你创建了lib/Transforms/Hello目录；最后，设置build脚本，用于编译新的pass。将以下代码拷贝到`lib/Transforms/Hello/CMakeLists.txt`。

```cmake
add_llvm_library( LLVMHello MODULE
  Hello.cp

  PLUGIN_TOOL
  opt
  )
```

将以下行加入到`lib/Transforms/CMakeLists.txt`

```cmake
add_subdirectory(Hello)
```

这个build脚本表示当前目录的Hello.cpp文件将被编译和链接成共享对象$(LEVEL)/lib/LLVMHello.so，能被opt工具通过-load选项动态加载。

#### （2）写Helllo.cpp

首先需要添加头文件，因为在写 [Pass](http://llvm.org/doxygen/classllvm_1_1Pass.html)，在函数 [Function](http://llvm.org/doxygen/classllvm_1_1Function.html)上操作，且需要打印数据。

```c++
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
```

接下来，include文件中的函数落在llvm命名空间。

```c++
using namespace llvm;
```

接下来，开始一段匿名空间，匿名空间在c++中用到，c中采用static实现，定义在匿名空间中的变量只能在当前文件可见。

```c++
namespace{
```

接下来定义pass，定义Hello类，从[FunctionPass](https://llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-functionpass)类继承过来，每次处理一个函数。

```c++
struct Hello : public FunctionPass {
static char ID;
Hello() : FunctionPass(ID) {}
```

声明 [runOnFunction](https://llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-runonfunction) 方法，重写从 [FunctionPass](https://llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-functionpass)继承来的同名虚函数。runOnFunction()就是以函数为单位进行处理，LLVM会以一次一个function为单位，喂进来给你处理，接下来就是将喂进来的function的名字打印出来。

```c++
  bool runOnFunction(Function &F) override {
    errs() << "Hello: ";
    errs().write_escaped(F.getName()) << '\n';
    return false;
  }
}; // end of struct Hello
}  // end of anonymous namespace
```

初始化pass的ID，LLVM使用ID地址来识别pass，所以所用初始值不重要。

```c++
char Hello::ID = 0;
```

最后，注册Hello类，给一个命令行参数"hello"和一个名字"Hello World Pass"，最后两个参数描述它的行为：如果pass需要修改CFG则第3个参数设为true，若pass是一个analysis pass，例如dominator tree pass，则第4个参数设为true。

```c++
static RegisterPass<Hello> X("hello", "Hello World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
```

如果要将本pass注册为现有流水线中的一步，则还需要一些扩展。eg，加到优化步骤之前则用`PassManagerBuilder::EP_EarlyAsPossible`；加到优化之后则用`PassManagerBuilder::EP_FullLinkTimeOptimizationLast`。

```c++
static llvm::RegisterStandardPasses Y(
	llvm::PassManagerBuilder::EP_EarlyAsPossible,
	[](const llvm::PassManagerBuilder &Builder,
		llvm::legacy::PassManagerBase &PM) { PM.add(new Hello()); });
```



整个代码.cpp文件如下：

```c++
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
struct Hello : public FunctionPass {
  static char ID;
  Hello() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
    errs() << "Hello: ";
    errs().write_escaped(F.getName()) << '\n';
    return false;
  }
}; // end of struct Hello
}  // end of anonymous namespace

char Hello::ID = 0;
static RegisterPass<Hello> X("hello", "Hello World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
static llvm::RegisterStandardPasses Y(
	llvm::PassManagerBuilder::EP_EarlyAsPossible,
	[](const llvm::PassManagerBuilder &Builder,
		llvm::legacy::PassManagerBase &PM) { PM.add(new Hello()); });
```

在顶层LLVM根目录下创建build目录，在build目录下先"cmake ../"，再"make"即可生成`lib/LLVMHello.so`文件。

#### （3）使用opt运行pass

生成共享目标文件后，由于已经通过`RegisterPass`注册过了，所以可以使用opt命令通过你的pass运行LLVM程序。首先参考[Getting Started with the LLVM System](https://llvm.org/docs/GettingStarted.html)编译"Hello World"为bitcode文件(hello.bc)，通过以下命令运行hello.bc（"-load"表示加载pass库）：

```bash
$ opt -load lib/LLVMHello.so -hello < hello.bc > /dev/null
Hello: __main
Hello: puts
Hello: main
```

## 3.Pass类和需求

设计一个pass首先要考虑需要继承哪一个类，Hello World例子使用了[FunctionPass](https://llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-functionpass)类来实现，接下来看看其它可用的类。

#### （1）[ImmutablePass](http://llvm.org/doxygen/classllvm_1_1ImmutablePass.html)类

这个类比较无聊，这个类用在不用运行、不会改变状态、不需要更新的pass，在转化和分析中不常用到，但能提供当前编译器配置信息。尽管这个类不常用到，但是能提供当前被编译的目标机的信息，以及影响转化的静态信息。

#### （2）[ModulePass](http://llvm.org/doxygen/classllvm_1_1ModulePass.html)类

最常用的一个类，使用该类表示将整个程序当做一个单元，可以随意引用函数主体，添加和移除函数。由于不知道ModulePass子类的行为，不能作优化。

`ModulePass`可以使用函数级passes（如dominators，函数级pass使用`getAnalysis`接口，也即`getAnalysis<DominatorTree>(llvm::Function *)`来提供获取分析结果的一个函数）。写`ModulePass`时需要重写`runOnModule`函数，该函数完成pass的主要工作，如果原IR发生修改则返回True，如果只是分析，则返回False。

#### （3）[CallGraphSCCPass](http://llvm.org/doxygen/classllvm_1_1CallGraphSCCPass.html)类

在调用图上从后往前遍历程序。`CallGraphSCCPass`可以帮助构建和遍历调用图。`CallGraphSCCPass`子类需满足的要求：只能监控和修改当前SCC、SCC的直接调用者和直接被调用者，不能监控和修改其他`Function`；需要保存当前`CallGraph`对象，显示对代码做了哪些修改；不能从当前Module添加/去除SCC，但可以增减全局变量；调用`runOnSCC`之间能保持状态（包括全局变量）。

需重写以下函数：

- `doInitialization(CallGraph &)`：能做`CallGraphSCCPass`不允许的事情，如增减函数、获取指向函数的指针。
- `runOnSCC`：完成pass的主要工作。
- `doFinalization(CallGraph &)`：很少使用，在pass调用完`runOnSCC`之后才调用它。

#### （4） [FunctionPass](http://llvm.org/doxygen/classllvm_1_1Pass.html)类

FunctionPass处理程序中每个函数，并不依赖其他函数的结果，FunctionPass不需要它们按特定顺序执行，不会修改外部函数。

`FunctionPass`子类的要求：只能监控和修改当前被处理的`Function`；不能从当前`Module`增减`Function`、全局变量；调用`runOnFunction`之间不能保持状态（包括全局变量）。

需重写以下函数：

- `doInitialization(Module &)`：能做`FunctionPass`不允许的事情，如增减函数、获取指向函数的指针。使用示例见[LowerAllocations](https://llvm.org/doxygen/LowerAllocations_8cpp-source.html) pass，该pass将`malloc`、`free`指令转化为`malloc()`和`free()`函数调用，它使用`doInitialization`函数对`malloc`和`free`函数的索引，如果有需要，则往module添加prototypes。
- `runOnFunction`函数：完成pass的主要工作，转化或分析。
- `doFinalization(Module &)`函数：很少使用，在pass调用完`runOnFunction`之后才调用它。

#### （5） [LoopPass](https://llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-looppass)类

LoopPass遍历处理函数中的loop，并不依赖函数中其他loop。遍历时遇到嵌套循环，最外面的循环最后处理。`LoopPass`的子类可以使用`LPPassManager`接口来更新loop。

如果把`LoopPass`的子类嵌入到main loop pass流水线中去运行，则需要保存其他loop pass需要用到的function分析。`LoopUtils.h`提供了`getLoopAnalysisUsage`函数，可以在子类的`getAnalysisUsage`重载中调用。

需重写以下函数：

- `doInitialization(Loop *, LPPassManager &)`：可以使用`LPPassManager`接口来访问`Function`或`Module`级分析信息。
- `runOnLoop`：完成pass的主要工作，即代码转换或分析。
- `doFinalization()`

#### （6）RegionPass

和`LoopPass`类似，但只处理函数中单入口单退出的区域。

需重写的函数：

- `doInitialization(Region *, RGPassManager &)`：可以使用`LPPassManager`接口来访问`Function`或`Module`级分析信息。
- `runOnRegion`
- `doFinalization()`

#### （7）MachineFunctionPass类

是LLVM code generator的一部分，依赖机器类型。Code generator passes采用`TargetMachine::addPassesToEmitFile`来注册和初始化，所以不能通过`opt`或`bugpoint`命令来运行。`MachineFunctionPass`也属于`FunctionPass`，所以和`FunctionPass`的限制一样，此外`MachineFunctionPass`还不能修改和创建 LLVM IR `Instruction`、`BasicBlock`、`Argument`、`Function`、`GlobalVariable`、`GlobalAlias`、`Module`，只能修改当前正被处理的`MachineFunction`，调用`runOnMachineFunction`不能保持状态。

需重写的函数：

- `runOnMachineFunction(MachineFunction &MF)`：`MachineFunctionPass`的主入口点，完成pass主要工作。每遇到`Module`中的一个`MachineFunction`都调用`runOnMachineFunction`函数。

#### （8）pass注册

前面`Hello World` pass已经展示了如何注册，采用`RegisterPass`调用。

待实现的函数：

- `print`函数：`virtual void print(llvm::raw_ostream &O, const Module *M) const;`

  用于打印分析结果，对于调试和展示该分析如何工作很有用，使用opt的`-analyze`参数来调用此函数。`llvm::raw_ostream`参数确定了打印结果采用什么流，`Module`参数是指向程序的顶层模块的指针，当从调试器调用`Pass::dump()`时该指针可为`NULL`。

- pass之间的联系：`PassManager`负责pass之间的联系和依赖（决定执行顺序），每个pass可以声明必须在它之前执行的pass。如果某pass未实现`getAnalysisUsage`函数，则默认没有要预先执行的pass。

- `getAnalysisUsage`：`virtual void getAnalysisUsage(AnalysisUsage &Info) const;`

  实现时需用`required`和`invalidated` pass填充[AnalysisUsage](https://llvm.org/doxygen/classllvm_1_1AnalysisUsage.html)对象，通过以下函数来实现：

  - `AnalysisUsage::addRequired<>` & `AnalysisUsage::addRequiredTransitive<>`：定义必须在本pass之前执行的pass，如`DominatorSet`、`BreakCriticalEdges`。有些分析需要和其他分析一起才能正常工作，如`AliasAnalysis <AliasAnalysis>`实现需要链接到其他分析pass，这时候要用到`addRequiredTransitive`函数，而非`addRequired`函数（表示只要`the requiring pass`在运行，过渡的`required pass`也要保持运行）。
  - `AnalysisUsage::addPreserved<>`：`setPreservesAll`表示pass不会修改LLVM程序；`setPreservesCFG`表示会修改指令但不会修改CFG或终止指令；`addPreserved`适用于代码转换类的pass，如`BreakCriticalEdges`。

  `getAnalysisUsage`实现示例：

  ```c++
    // This example modifies the program, but does not modify the CFG
    void LICM::getAnalysisUsage(AnalysisUsage &AU) const {
      AU.setPreservesCFG();
      AU.addRequired<LoopInfoWrapperPass>();
    }
  ```

  

- `getAnalysis<>`和`getAnalysisIfAvailable<>`：`Pass::getAnalysis<>`自动从你实现的类中继承，它使你能访问之前用`getAnalysisUsage`声明的pass，只需要1个参数来指定需要哪个pass类，然后返回对该pass的引用。

  例如：如果你试图获取一个没在`getAnalysisUsage`中声明的分析，则会报错。可在你的`run*`函数中调用它。

  ```c++
    bool LICM::runOnFunction(Function &F) {
      LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
      //...
    }
  ```

  还有个优点，该接口使你能在module级pass中使用函数级分析，例如：pass manager会在返回索引之前调用`DominatorTree`。

  ```c++
    bool ModuleLevelPass::runOnModule(Module &M) {
      //...
      DominatorTree &DT = getAnalysis<DominatorTree>(Func);
      //...
    }
  ```

  如果你的pass可以更新分析，可以使用`getAnalysisIfAvailable`方法，如果分析是active的则返回一个指针。

  ```c++
    if (DominatorSet *DS = getAnalysisIfAvailable<DominatorSet>()) {
      // A DominatorSet is active.  This code will update it.
    }
  ```

#### （9）实现Analysis Groups

说明：有些复杂的分析，如流敏感、上下文敏感的过程间分析需要很多分析配合一起实现。如果其他pass想使用Analysis groups，也需要调用`AnalysisUsage::addRequired()`和`Pass::getAnalysis()`来获取，但使用`PassManager`更简单。Analysis group也需要使用`RegisterAnalysisGroup`来注册，并调用`INITIALIZE_AG_PASS`宏来整合。示例可以看看[AliasAnalysis](https://llvm.org/doxygen/classllvm_1_1AliasAnalysis.html)。

- `RegisterAnalysisGroup`：`RegisterAnalysisGroup`用于注册Analysis group，`INITIALIZE_AG_PASS`宏用于将pass实现添加到analysis group。

  `static RegisterAnalysisGroup<AliasAnalysis> A("Alias Analysis");`

  注册完分析之后，pass可以利用以下代码来声明有效的接口实现：表示`FancyAA`类使用`INITIALIZE_AG_PASS`宏来注册和整合到[`AliasAnalysis`](https://llvm.org/doxygen/classllvm_1_1AliasAnalysis.html) analysis group中。

  ```c++
    namespace {
      // Declare that we implement the AliasAnalysis interface
      INITIALIZE_AG_PASS(FancyAA, AliasAnalysis , "somefancyaa",
          "A more complex alias analysis implementation",
          false,  // Is CFG Only?
          true,   // Is Analysis?
          false); // Is default Analysis Group implementation?
    }
  ```

  以下代码展示如何指定默认的实现（由`INITIALIZE_AG_PASS`的最后一个参数确定），一个Analysis Group必须有一个默认实现（该默认实现可以从`ImmutablePass`继承），例如[`BasicAliasAnalysis`](https://llvm.org/doxygen/structBasicAliasAnalysis.html)就是该接口的默认实现。

#### （10）Pass [Statistic](http://llvm.org/doxygen/Statistic_8h_source.html)类

**介绍**：命令行加上`-stats`选项后，就会在运行的结尾打印数据，详情可参考Programmer's Manual中的`Statistics section <Statistic>`。

**PassManager功能**：[PassManager](https://llvm.org/doxygen/PassManager_8h_source.html)的[class](https://llvm.org/doxygen/classllvm_1_1PassManager.html)可以保证很多pass以正确的顺序、高效的运行。

- 1.共享分析结果：避免重复分析。`PassManager`可以追踪所有分析结果的生存周期，展示哪些分析已经已经完成并且可用。
- 2.pass流水化执行：以高效的使用cache和内存。具体来说，给定连续的`FunctionPass`，它将先对第1个函数执行所有的`FunctionPass`，再对第2个函数执行所有的`FunctionPass`，以此类推。一次只需计算1个[`DominatorSet`](https://llvm.org/doxygen/classllvm_1_1DominatorSet.html)，使cache更高效，也有利于进一步优化。

`PassManager`的有效性取决于开发者提供的信息，也即pass的行为。例如，如果开发者不实现`getAnalysisUsage`方法，则该pass无法被其他pass使用。

`PassManager`提供`--debug-pass`命令行选项，以对pass执行过程进行调试。如果想知道`--debug-pass`选项的变体，可使用`opt -help-hidden`命令查看。可以使用`-debug-pass=Structure`选项来查看指定pass如何与其他pass进行交互的，例如：

```bash
# Hello World pass之后运行gvn pass、licm pass
$ opt -load lib/LLVMHello.so -gvn -licm --debug-pass=Structure < hello.bc > /dev/null
  ModulePass Manager
    FunctionPass Manager
      Dominator Tree Construction
      Basic Alias Analysis (stateless AA impl)
      Function Alias Analysis Results
      Memory Dependence Analysis
      Global Value Numbering
      Natural Loop Information
      Canonicalize natural loops
      Loop-Closed SSA Form Pass
      Basic Alias Analysis (stateless AA impl)
      Function Alias Analysis Results
      Scalar Evolution Analysis
      Loop Pass Manager
        Loop Invariant Code Motion
      Module Verifier
    Bitcode Writer
```

以上输出结果显示了pass创建时间。GVN pass使用了dominator tree信息，LICM pass使用了loop信息（loop信息也使用了dominator tree）。LICM pass运行完后，自动运行`module verifier`，它会使用dominator tree来检查生成的LLVM code是否正确。注意：dominator tree只计算了一次，被3个pass共享。

```bash
# Hello World pass在gvn pass、licm pass中间运行
$ opt -load lib/LLVMHello.so -gvn -hello -licm --debug-pass=Structure < hello.bc > /dev/null
  ModulePass Manager
    FunctionPass Manager
      Dominator Tree Construction
      Basic Alias Analysis (stateless AA impl)
      Function Alias Analysis Results
      Memory Dependence Analysis
      Global Value Numbering
      Hello World Pass
      Dominator Tree Construction
      Natural Loop Information
      Canonicalize natural loops
      Loop-Closed SSA Form Pass
      Basic Alias Analysis (stateless AA impl)
      Function Alias Analysis Results
      Scalar Evolution Analysis
      Loop Pass Manager
        Loop Invariant Code Motion
      Module Verifier
    Bitcode Writer
  Hello: __main
  Hello: puts
  Hello: main
```

以上输出结果显示`Hello World` pass 终止了Dominator Tree pass，接下来的pass会再次调用Dominator Tree pass获取dominator信息，为了修复这个问题，需实现`getAnalysisUsage`方法：

```c++
  // We don't modify the program, so we preserve all analyses
  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }
```



```bash
# 修复成功，dominator信息不会被计算两次
$ opt -load lib/LLVMHello.so -gvn -hello -licm --debug-pass=Structure < hello.bc > /dev/null
  Pass Arguments:  -gvn -hello -licm
  ModulePass Manager
    FunctionPass Manager
      Dominator Tree Construction
      Basic Alias Analysis (stateless AA impl)
      Function Alias Analysis Results
      Memory Dependence Analysis
      Global Value Numbering
      Hello World Pass
      Natural Loop Information
      Canonicalize natural loops
      Loop-Closed SSA Form Pass
      Basic Alias Analysis (stateless AA impl)
      Function Alias Analysis Results
      Scalar Evolution Analysis
      Loop Pass Manager
        Loop Invariant Code Motion
      Module Verifier
    Bitcode Writer
  Hello: __main
  Hello: puts
  Hello: main
```

**`releaseMemory`方法**：`virtual void releaseMemory();`——`PassManager`自动确定何时开始运行分析、分析结果保存多久，如果不再用到了，需要用`releaseMemory`释放内存。

#### （11）构建pass 插件

LLVM提供了一种机制，可以在clang、opt、bugpoint内自动注册pass插件。首先要创建一个独立的project，添加到`tools/`，或者使用`MonoRepo`布局，跟其他project并列。该project的`CMakeLists.txt`如下所示：

```cmake
add_llvm_pass_plugin(Name source0.cpp)
```

该pass需为新的pass manager提供两个入口点，一个用来静态注册，一个用来动态加载插件：

- `llvm::PassPluginLibraryInfo get##Name##PluginInfo();`
- `extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() LLVM_ATTRIBUTE_WEAK;`

pass插件默认是动态编译和链接的，可以修改`LLVM_${NAME}_LINK_INTO_TOOLS`变量来修改，`ON`表示将该project静态链接。可使用以下代码来加载静态链接的pass插件：

```c++
// fetch the declaration
#define HANDLE_EXTENSION(Ext) llvm::PassPluginLibraryInfo get##Ext##PluginInfo();
#include "llvm/Support/Extension.def"

[...]

// use them, PB is an llvm::PassBuilder instance
#define HANDLE_EXTENSION(Ext) get##Ext##PluginInfo().RegisterPassBuilderCallbacks(PB);
#include "llvm/Support/Extension.def"
```

#### （12）注册可动态加载的pass

pass注册的主要机制是`MachinePassRegistry`类和`MachinePassRegistryNode`的子类。`MachinePassRegistry`实例用于保存`MachinePassRegistryNode`对象组成的list，并且通过和命令行接口进行通信，对`MachinePassRegistryNode`对象进行增减。

`MachinePassRegistryNode`子类用于保存特定pass提供的信息，信息包含command line name, the command help string和用于创建pass实例的函数地址。



