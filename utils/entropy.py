from __future__ import print_function
import math

class Entropy():

    def calculate_shannon(self, data):
        '''
        Performs a Shannon entropy analysis on a given block of data.
        '''
        entropy = 0

        if data:
            length = len(data)

            seen = dict(((chr(x), 0) for x in range(0, 256)))
            for byte in data:
                seen[byte] += 1

            for x in range(0, 256):
                p_x = float(seen[chr(x)]) / length
                if p_x > 0:
                    entropy -= p_x * math.log(p_x, 2)

        return entropy

def main():
    fileName = "config.py"
    content = ""
    with open(fileName,'r') as file:
        content = file.read()
    
    entropyCalculator = Entropy()
    entropy = entropyCalculator.calculate_shannon(content)


    print("ENTROPY = {}".format(entropy))

if __name__ == '__main__':
    main()
    