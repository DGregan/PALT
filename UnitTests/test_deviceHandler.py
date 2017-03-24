from unittest import TestCase
from Handler import DeviceHandler
'''
assertEqual(a, b)
assertNotEqual
assertTrue
assertFalse
assertIs/IsNot
assertIsNone/IsNotNone
assertIn/NotIn
assertIsInstance/NotIsInstance

assertAlmostEqual/NotAlmostEqual
assertGreater/GreaterEqual
assertLess/LessEqual
assertRegex/NotRegex
assertCountEqual

assertMultiLineEqual
assertSequenceEqual
assertListEqual
assertTupleEqual
assertSetEqual
assertDictEqual
'''


class TestDeviceHandler(TestCase):
    def test_selected_device(self):
        self.found_devices = self.test_get_devices()



    def test_get_devices(self):
        '''
        TEST - Check if there are any network interface devices to be found
        :return: True if devices found
        '''
        self.dh = DeviceHandler()
        self.all_devices = self.dh.get_devices()
        self.assertIsNotNone(self.all_devices)
        return self.all_devices



