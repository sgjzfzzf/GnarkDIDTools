# GnarkDIDTools

该库为`GnarkDID`库的具体实现，共分为三个主要的模块`dcircuit`，`genkey`，`genpvk`。三部分共同组合，实现基于零知识证明的一个简易身份认证系统。注意使用前应该配置好本地的`Go`环境，否则可能出现无法正常运行的情况。

该实现中椭圆曲线选用`BN254`，数字签名哈希函数为`Mimc`，字符串哈希函数为`SHA256`。

## dcircuit

使用该部分时，首先向`dcircuit.go`文件的预留部分按照Gnark语法添加约束用于电路描述。接下来该部分包含三个子部分可用于执行。首先介绍电路的描述格式

### json

本库使用`json`文件对电路进行描述，具体格式例子如下

```json
{
    "ID": 1,
    "Name": "Alice",
    "BirthYear": 2000,
    "Income": 10000,
    "GraduationSchool": "Shanghai Jiao Tong University",
    "Gender": "Female",
    "Property": 10000,
    "Citizenship": "China"
}
```

该类型的文件会作为输入对电路的参数进行描述。

### genproof

该子部分用于生成proof。使用格式如下

```bash
go run ./genproof/genproof.go [opt]
opt:
	-o(--out) #the name of output proof file name
	-i(--input) #the name of the json file representing witness
	-k(--key) #the name of private key file name
	-p(--pkey) #the name of prooving key file name
	-r(--r) #the name of r1cs file name
```

用例如下

```bash
go run ./genproof/genproof.go -i mywitness.json -k mysk.bk -p mypk.pk -r myr1cs.r1cs -o myproof.proof
```

该指令会使用`mywitness.json`作为witness文件，`mysk.bk`作为私钥，`mypk.pk`作为证明密钥，`myr1cs.r1cs`作为电路文件，输出`myproof.proof`作为证明文件。

该指令`-o`参数可以省略，则默认输出文件名为`proof`。

### genr1cs

该子部分用于生成r1cs电路。在`dircuit.go`文件中完成对电路的约束后即可使用。使用格式如下

```bash
go run ./genr1cs/genr1cs.go [opt]
opt:
	-o(--out) #the name of output r1cs file, just the former part
```

用例如下

```
go run ./genr1cs/genr1cs.go -o mycircuit
```

该指令会基于`dircuit.go`生成`mycircuit.r1cs`文件。

该指令参数`-o`可省略，则默认输出文件名为`dcircuit`。

### verify

该子部分用于验证证明是否成立。使用格式如下

```bash
go run ./verify/verify.go [opt]
opt:
	-p(--proof) #the name of proof file
	-v(--vkey) #the name of verifying key file
	-k(--pkey) #the name of public key file
```

用例如下

```bash
go run ./verify/verify.go -p myproof.proof -v myvk.vk -k mypk.bk.pub
```

该指令会使用`myproof.proof`作为证明文件，`myvk.vk`作为证明密钥，`mypk.bk.pub`作为公钥进行验证。如果验证成功输出`Right.`，否则输出`Wrong.`和错误原因。

## genkey

该模块主要用于生成数字签名的公私钥文件，其中公钥文件保存后缀为`.bk.pub`，私钥文件保存后缀为`.bk`。使用格式如下

```bash
go run genkey.go [opt]
opt:
	-o(--out) #the name of output key file, just the former part
	-s(--seed) #the random seed for the key generation in the form of string
```

用例如下

```bash
go run genkey.go -o mykey -s "Hello, Gnark!"
```

该指令会以"Hello, Gnark!"字符串为随机种子，生成名为`mykey.bk`与`mykey.bk.pub`两份文件。

该指令参数可省略，则默认文件输出名为`key`，随机种子采用随机数生成256位字符串。

## genpvk

该模块主要用于生成证明用的生成密钥和验证密钥，输出后缀分别位.pk，.vk。使用格式如下

```bash
go run genpvk.go [opt]
opt:
	-o(--out) #the name of output key file, just the former part
	-i(--input) #the name of input r1cs file, cannot ignore
```

用例如下

```bash
go run genpvk.go -o pvk -i circuit.r1cs
```

该指令会读入`circuit.r1cs`文件并输出`pvk.pk`和`pvk.vk`两个文件。

该指令`-o`参数可省略，默认名称`key`。

## 使用流程

在使用该库时，流程如下

1. 利用`genkey`生成公私钥，发布公钥
2. 在`./dcircuit/dcircuit.go`文件中添加完整的约束信息，然后使用`genr1cs`子部分生成r1cs文件
3. 利用`genpvk`模块生成用于证明的`proofkey`和`verifykey`
4. 利用`genproof`模块生成证明
5. 利用`verify`模块检验证明