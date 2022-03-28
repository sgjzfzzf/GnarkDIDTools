from logging import error
import os

from sympy import true


def movefile(filename: str, ddir: str, sdir: str) -> None:
    f1name = "{}/{}".format(sdir, filename)
    f2name = "{}/{}".format(ddir, filename)
    f1 = open(f1name, 'rb')
    f2 = open(f2name, 'wb')
    f2.write(f1.read())
    f1.close()
    f2.close()
    os.remove(f1name)


def genproof(out: str = None, in_: str = None, pkey: str = None, r1cs: str = None) -> None:
    s = "go run ./genproof/genproof.go"
    if out is not None:
        out = os.path.abspath(out)
        s += " --out {}".format(out)
    if in_ is None:
        raise error("no input")
    else:
        in_ = os.path.abspath(in_)
        s += " --in {}".format(in_)
    if pkey is None:
        raise error("no proving key")
    else:
        pkey = os.path.abspath(pkey)
        s += " --pkey {}".format(pkey)
    if r1cs is None:
        raise error("no r1cs")
    else:
        r1cs = os.path.abspath(r1cs)
        s += " --r1cs {}".format(r1cs)
    wdir = "./dcircuit"
    os.chdir(wdir)
    os.system(s)
    os.chdir("..")
    proofdir = "./proof"
    if not os.path.isdir(proofdir):
        os.mkdir(proofdir)
    for _, _, files in os.walk(wdir):
        for file in files:
            _, end = os.path.splitext(file)
            if end == ".proof":
                movefile(file, proofdir, wdir)


def genr1cs(out: str = None) -> None:
    s = "go run ./genr1cs/genr1cs.go"
    if out is not None:
        out = os.path.abspath(out)
        s += " --out {}".format(out)
    wdir = "./dcircuit"
    os.chdir(wdir)
    os.system(s)
    os.chdir("..")
    r1csdir = "./r1cs"
    if not os.path.isdir(r1csdir):
        os.mkdir(r1csdir)
    for _, _, files in os.walk(wdir):
        for file in files:
            _, end = os.path.splitext(file)
            if end == ".r1cs":
                movefile(file, r1csdir, wdir)


def genwitness(out: str = None, in_: str = None, key: str = None) -> None:
    s = "go run ./genwitness/genwitness.go"
    if out is not None:
        out = os.path.abspath(out)
        s += " --out {}".format(out)
    if in_ is None:
        raise error("no input")
    else:
        in_ = os.path.abspath(in_)
        s += " --in {}".format(in_)
    if key is None:
        raise error("no key")
    else:
        key = os.path.abspath(key)
        s += " --key {}".format(key)
    wdir = "./dcircuit"
    os.chdir(wdir)
    os.system(s)
    os.chdir("..")
    witdir = "./witness"
    if not os.path.isdir(witdir):
        os.mkdir(witdir)
    for _, _, files in os.walk(wdir):
        for file in files:
            _, end = os.path.splitext(file)
            if end == ".wit":
                movefile(file, witdir, wdir)


def verify(proof: str = None, vkey: str = None, pubkey: str = None, id: str = None) -> bool:
    s = "go run ./verify/verify.go"
    if proof is None:
        raise error("no proof")
    else:
        proof = os.path.abspath(proof)
        s += " --proof {}".format(proof)
    if vkey is None:
        raise error("no verifying key")
    else:
        vkey = os.path.abspath(vkey)
        s += " --vkey {}".format(vkey)
    if pubkey is None:
        raise error("no proving key")
    else:
        pubkey = os.path.abspath(pubkey)
        s += " --pubkey {}".format(pubkey)
    if id is None:
        raise error("no id")
    else:
        s += " --id {}".format(id)
    wdir = "./dcircuit"
    os.chdir(wdir)
    out = os.popen(s)
    res = out.read()
    if res == "Right.\n":
        return True
    elif res[:7] == "Wrong.\n":
        print(res)
        return False
    else:
        print(res)
        raise error("error happend")


def genkey(out: str = None, seed: str = None) -> None:
    s = "go run ./genkey.go"
    if out is not None:
        out = os.path.abspath(out)
        s += " --out {}".format(out)
    if seed is not None:
        s += " --seed {}".format(seed)
    wdir = "./genkey"
    os.chdir(wdir)
    os.system(s)
    os.chdir("..")
    keydir = "./key"
    if not os.path.isdir(keydir):
        os.mkdir(keydir)
    for _, _, files in os.walk(wdir):
        for file in files:
            _, end = os.path.splitext(file)
            if end == ".bk" or end == ".pub":
                movefile(file, keydir, wdir)


def genpvk(out: str = None, in_: str = None) -> None:
    s = "go run ./genpvk.go"
    if out is not None:
        out = os.path.abspath(out)
        s += " --out {}".format(out)
    if in_ is None:
        raise error("no input")
    else:
        in_ = os.path.abspath(in_)
        s += " --in {}".format(in_)
    wdir = "./genpvk"
    os.chdir(wdir)
    os.system(s)
    os.chdir("..")
    pvkdir = "./pvk"
    if not os.path.isdir(pvkdir):
        os.mkdir(pvkdir)
    for _, _, files in os.walk(wdir):
        for file in files:
            _, end = os.path.splitext(file)
            if end == ".pk" or end == ".vk":
                movefile(file, pvkdir, wdir)


# Example: you can excute the following example to test the whole program
# genkey()
# genr1cs()
# genpvk(in_="./r1cs/dcircuit.r1cs")
# genwitness(in_="./dcircuit/test/dcircuit_obj.json", key="./key/key.bk")
# genproof(in_="./witness/witness.wit",
#          pkey="./pvk/key.pk", r1cs="./r1cs/dcircuit.r1cs")
# print(verify(proof="./proof/proof.proof",
#              vkey="./pvk/key.vk", pubkey="./key/key.bk.pub", id="1"))
