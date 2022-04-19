from menu import *
import unittest


class GnarkToolTest1(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        self.cur = os.path.abspath(os.path.curdir)
        super().__init__(methodName)

    def setUp(self) -> None:
        os.chdir(self.cur)
        genkey()
        genr1cs()
        genpvk(in_="./r1cs/dcircuit.r1cs")
        return super().setUp()

    def test_example_1(self):
        genwitness(in_="./dcircuit/test/Alice.json", key="./key/key.bk")
        genproof(in_="./witness/witness.wit",
                 pkey="./pvk/key.pk", r1cs="./r1cs/dcircuit.r1cs")
        res = verify(proof="./proof/proof.proof",
                     vkey="./pvk/key.vk", pubkey="./key/key.bk.pub", id="1")
        self.assertEqual(res, False)

    def test_example_2(self):
        genwitness(in_="./dcircuit/test/Bob.json", key="./key/key.bk")
        genproof(in_="./witness/witness.wit",
                 pkey="./pvk/key.pk", r1cs="./r1cs/dcircuit.r1cs")
        res = verify(proof="./proof/proof.proof",
                     vkey="./pvk/key.vk", pubkey="./key/key.bk.pub", id="341928501")
        self.assertEqual(res, False)

    def test_example_3(self):
        genwitness(in_="./dcircuit/test/Carol.json", key="./key/key.bk")
        genproof(in_="./witness/witness.wit",
                 pkey="./pvk/key.pk", r1cs="./r1cs/dcircuit.r1cs")
        res = verify(proof="./proof/proof.proof",
                     vkey="./pvk/key.vk", pubkey="./key/key.bk.pub", id="3")
        self.assertEqual(res, True)


if __name__ == "__main__":
    unittest.main()
