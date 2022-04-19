from logging import error
import os


def genproof(out: str = None, in_: str = None, pkey: str = None, r1cs: str = None) -> None:
    proofdir = "./proof"
    if not os.path.isdir(proofdir):
        os.mkdir(proofdir)
    s = "go run ./genproof/genproof.go"
    if out is not None:
        out = os.path.abspath("{}/{}".format(proofdir, out))
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


def genr1cs(out: str = None) -> None:
    r1csdir = "./r1cs"
    if not os.path.isdir(r1csdir):
        os.mkdir(r1csdir)
    s = "go run ./genr1cs/genr1cs.go"
    if out is not None:
        out = os.path.abspath("{}/{}".format(r1csdir, out))
        s += " --out {}".format(out)
    wdir = "./dcircuit"
    os.chdir(wdir)
    os.system(s)
    os.chdir("..")


def genwitness(out: str = None, in_: str = None, key: str = None) -> None:
    witdir = "./witness"
    if not os.path.isdir(witdir):
        os.mkdir(witdir)
    s = "go run ./genwitness/genwitness.go"
    if out is not None:
        out = os.path.abspath("{}/{}".format(witdir, out))
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
    out.close()
    if res == "Right.\n":
        return True
    elif res[:7] == "Wrong.\n":
        print(res)
        return False
    else:
        print(res)
        raise error("error happend")


def genkey(out: str = None, seed: str = None) -> None:
    keydir = "./key"
    if not os.path.isdir(keydir):
        os.mkdir(keydir)
    s = "go run ./genkey.go"
    if out is not None:
        out = os.path.abspath("{}/{}".format(keydir, out))
        s += " --out {}".format(out)
    if seed is not None:
        s += " --seed {}".format(seed)
    wdir = "./genkey"
    os.chdir(wdir)
    os.system(s)
    os.chdir("..")


def genpvk(out: str = None, in_: str = None) -> None:
    pvkdir = "./pvk"
    if not os.path.isdir(pvkdir):
        os.mkdir(pvkdir)
    s = "go run ./genpvk.go"
    if out is not None:
        out = os.path.abspath("{}/{}".format(pvkdir, out))
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
