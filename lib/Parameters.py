import random
from Crypto.Hash import SHAKE256

from .FP import FP
from .ECPoint import ECPoint

class Parameters:
    def __init__(self, xa=None, ya=None, xb=None, yb=None):
        self.p= 2**256 - 2**224 + 2**192 + 2**96 - 1
        self.a=FP(-3,self.p)
        self.b=FP(41058363725152142129326129780047268409114441015993725554835256314039467401291,self.p)
        x=FP(48439561293906451759052585252797914202762949526041747995844080717082404635286,self.p)
        y=FP(36134250956749795798585127919587881956611106672985015071877198253568414405109,self.p)
        self.q=2**256 - 2**224 + 2**192 - 89188191075325690597107910205041859247
        self.G=ECPoint(self.a,self.b, x,y)

        if (xa != None and ya != None and xb != None and yb != None):
            self.A=ECPoint(self.a,self.b, FP(xa,self.p),FP(ya,self.p))
            self.B=ECPoint(self.a,self.b, FP(xb,self.p),FP(yb,self.p))
        else:
            self.A=None
            self.B=None

    @staticmethod
    def get_public_element():
        param=Parameters()
        c=random.randint(1, param.q-1)
        return param.G.point_multiplication(c)

    def validate_point(self, ec_point):
        three = FP(3,self.a.p)
        y_r = ec_point.y ** 2
        x_r = ec_point.x ** 3 - (three * ec_point.x) + self.b
        if y_r != x_r or ECPoint(self.a, self.b, x=x_r, y=y_r).is_identity():
            raise ValueError('Point not valid')

    def get_unique_H(self, idp, inputs, n=32):
        h_256 = SHAKE256.new()
        fixed_idp = bytes(f"fixed_idp_{idp}", 'utf-8')

        h_256.update(fixed_idp)
        for input in inputs:
           h_256.update(input)

        return h_256.read(n)

