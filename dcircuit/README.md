# Default Circuit

这是默认提供的电路文件。当生成电路时，只需在dircuit.go文件中的预留部分按照Gnark的语法添加相应的约束即可。

该类提供的标准输入方式为json文件，Prover只需按照标准格式填写json即可进行后续的步骤，参考test文件了解如何进行文件初始化和电路初始化。

若需要编译生成电路文件，则输入指令 make r1cs OUTPUT="电路文件名"，若OUTPUT置空，则命名为dcircuit.r1cs。