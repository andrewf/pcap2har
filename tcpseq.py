

def twos_comp(x):
    return ~(x-1)

def subtract(a, b):
    '''Calculate the difference between a and b, two python integers,
    in a manner suitable for comparing two TCP sequence numbers in a
    wrap-around-sensitive way.'''
    return (a + twos_comp(b)) & 0xffffffff

def lt(a, b):
    return subtract(a, b) < 0
    
import unittest

class TestTcpSeqSubtraction(unittest.TestCase):
    def testNormalSubtraction(self):
        self.assertEqual(subtract(500L, 1L), 499L)
        self.assertEqual(subtract(1L, 1L), 0L)
        self.assertEqual(subtract(0xffffffffL, 1L), 0xfffffffeL)
        #self.assertEqual(subtract(20L, 0x
    def testWrappedSubtraction(self):
        self.assertEqual(subtract(0, 0xffffffff), 1)
        self.assertEqual(subtract(0xffffffff, 0xfffffffe), 1)
        self.assertEqual(subtract(0, 1), -1)
        
def runtests():
    TcpSeqTestSuite = unittest.defaultTestLoader.loadTestsFromTestCase(TestTcpSeqSubtraction)
    runner = unittest.TextTestRunner()
    runner.run(TcpSeqTestSuite)