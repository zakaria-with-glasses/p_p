import math
import multiprocessing as mp

def tester(a,b,c):
    return math.log1p(a+b+c)

if __name__ == "__main__":
    with mp.Pool(2) as p:
        print(p.map(tester, [*(1,2,3,), *(3,4,5,)]))