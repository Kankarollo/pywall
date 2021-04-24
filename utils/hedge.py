from __future__ import print_function

import argparse
import sys
import bitarray
from time import time
import math
import os
import sp800_22_all_tests.sp800_22_approximate_entropy_test as test

class Hedge():

    def __init__(self):
        self.testlist = TESTLIST = [
            'frequency_within_block_test',
            'cumulative_sums_test',
            'runs_test',
            'approximate_entropy_test',
            ]

    def read_bits2(self,filename):
        a = bitarray.bitarray()
        with open(filename, 'rb') as fh:
            a.fromfile(fh)
        tmp=a.to01()
        n = len(a)
        ones = a.count()
        zeroes=n-ones
        s = abs(ones-zeroes)

        p = math.erfc(float(s)/(math.sqrt(float(n)) * math.sqrt(2.0)))

        success = (p >= 0.01)

        return map(int,tmp),success

    def execute_tests(self, filename, bigendian):
        bits,mono = self.read_bits2(filename)
        gotresult=False
        results = []

        if mono==False:
            print ("[DEBUG]: Mono=False")
            return results
        
        for testname in self.testlist:
            # print("TEST: %s" % testname)
            m = __import__ ("sp800_22_all_tests.sp800_22_"+testname)
            func = getattr(getattr(m,"sp800_22_"+testname),testname)
            (success,p,plist) = func(bits)
            summary_name = testname
            if success:
                print("ENCRYPTED")
                summary_result = "ENCRYPTED"
            else:
                print("NOT ENCRYPTED")
                summary_result = "NOT ENCRYPTED"

            if p != None:
                print("[DEBUG]: P="+str(p))
                summary_p = str(p)

            if plist != None:
                # for pval in plist:
                #     print("P="+str(pval))
                summary_p = str(min(plist))

            results.append((summary_name,summary_p, summary_result))
            if summary_result == "NOT ENCRYPTED":
                break
        
        return results

    def is_encrypted(self,results):
        val = 1
        is_encrypted = True
        for result in results:
            summary_name,summary_p, summary_result = result
            if summary_result=="NOT ENCRYPTED":
                is_encrypted = False
        return is_encrypted
        
    def print_summary(self,results):
        if not results:
            print("[DEBUG]: Mono=False")
            return
        print()
        print("SUMMARY")
        print("-------")
        print ("[DEBUG]: myresults=\n" + "\n".join(["Name:{} Result:{} ".format(el[0],el[2]) for el in results]))
        #print only one result
        if self.is_encrypted(results):
            print ("VERDICT:{}".format("ENCRYPTED"))
        else:
            print ("VERDICT:{}".format("NOT ENCRYPTED"))
            

def main(args):
    bigendian = args.be
    filename = args.filename
    hedge = Hedge()
    results = hedge.execute_tests(filename,bigendian)
    hedge.print_summary(results)
    # print("Tests of Distinguishability from Random")
    
    # bits = read_bits_from_file(filename,bigendian)
    
if __name__ == '__main__':
    import argparse
    import sys
    parser = argparse.ArgumentParser(description='Test data for distinguishability form random, using NIST SP800-22Rev1a algorithms.')
    parser.add_argument('filename', type=str, nargs='?', help='Filename of binary file to test')
    parser.add_argument('--be', action='store_false',help='Treat data as big endian bits within bytes. Defaults to little endian')
    parser.add_argument('-t', '--testname', default=None,help='Select the test to run. Defaults to running all tests. Use --list_tests to see the list')
    parser.add_argument('--list_tests', action='store_true',help='Display the list of tests')

    alltest_list = [
        'monobit_test',
        'frequency_within_block_test',
        'runs_test',
        'longest_run_ones_in_a_block_test',
        'binary_matrix_rank_test',
        'dft_test',
        'non_overlapping_template_matching_test',
        'overlapping_template_matching_test',
        'maurers_universal_test',
        'linear_complexity_test',
        'serial_test',
        'approximate_entropy_test',
        'cumulative_sums_test',
        'random_excursion_test',
        'random_excursion_variant_test']

    args = parser.parse_args()
    if not os.path.exists(str(args.filename)):
        print("[ERROR]: Wrong path to file.")
        parser.print_help()
        exit()
    if args.list_tests:
        for i,testname in zip(range(len(alltest_list)),alltest_list):
            print(str(i+1).ljust(4)+": "+testname)
        exit()

    main(args)