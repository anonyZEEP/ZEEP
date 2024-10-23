from py_ecc.bn128 import *
import random

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1
 
    if (m == 1):
        return 0
 
    while (a > 1):
 
        # q is quotient
        q = a // m
 
        t = m
 
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
 
        # Update x and y
        y = x - q * y
        x = t
 
    # Make x positive
    if (x < 0):
        x = x + m0
 
    return x

x = 21731386455322423618042034697444546263090381984227937918045676878719717021050
y1 = 7044058701174262396925018554117026457049145647792503833143887172752869638353
y2 = 19037960349915414855642376376440808296094164982377208394475900152153546694635
y3 = 11570716936416283644850549034510263629865900654576115657026011273796186373286
X = multiply(G1,x)
print("X")
print(X)
Y1 = multiply(G1,y1)
print("Y1")
print(Y1)
Y2 = multiply(G1,y2)
print("Y2")
print(Y2)
Y3 = multiply(G1,y3)
print("Y3")
print(Y3)

X_bar = multiply(G2,x)
print("X_bar")
print(X_bar)
Y1_bar = multiply(G2, y1)
print("Y1_bar")
print(Y1_bar)
Y2_bar = multiply(G2, y2)
print("Y2_bar")
print(Y2_bar)
Y3_bar = multiply(G2, y3)
print("Y3_bar")
print(Y3_bar)

epoch = 21485779060700466346946932037436823033493279503841639388317419980269586795590
r = 7030271943230207668318928471301649924809590528879102177287208801932835410278
t1 = 5932446027950534581386297688127490222552607728328385359879206271382747248726
t2 = 1175723036334622269525680674001167106865976947702405789431642993820861090805
commitment = add(add(multiply(Y1, t1), multiply(Y2, t2)), multiply(G1, r))
print("commitment")
print(commitment)
commitment_dash = add(commitment, multiply(Y3, epoch))
print("commitment_dash")
print(commitment_dash)
u = 6327927046234122005075131287496177601084411695310373284745052259526490914254
sig1 = multiply(G1, u)
print("sig1")
print(sig1)

sig2 = multiply(add(X, commitment_dash), u)
print("sig2")
print(sig2)

r = ((-r)%curve_order)
if(r<0):
    r = r + curve_order
sig2_dash = add(sig2, multiply(sig1, r))
print("sig2_dash")
print(sig2_dash)

Y1_bar_t1 = multiply(Y1_bar, t1)
print("Y1_bar_t1 = " )
print(Y1_bar_t1)
Y1_bar_t2 = multiply(Y2_bar, t2)
print("Y1_bar_t2 = " )
print(Y1_bar_t2)
Y1_bar_e = multiply(Y3_bar, epoch)
print("Y1_bar_e = " )
print(Y1_bar_e)

total  = add(add(X_bar, Y1_bar_t1), add(Y1_bar_t2, Y1_bar_e))
print("total")
print(total)

pai1 = pairing(total, sig1)
print("pai1")
print(pai1)

pai2 = pairing(G2, sig2_dash)
print("pai2")
print(pai2)

print(pai1 == pai2)
# id = 
# epoc = 
# # m_dash = 19973877484081113936941708616559737546143149472075925685142248221861279799073
# # h = [11630579511047253714426198921801720441789597957707552691607459572517910716458, 102700184059941952208353663545406435649076501871322097382329919821364119621]
# # h = (FQ(h[0]),FQ(h[1]))
# # temp = (x+((ms1*y1)%curve_order) + ((ms2*y2)%curve_order) + ((m_dash*y3)%curve_order))%curve_order
# # print(temp)
# # sig = multiply(h, temp)
# # print(sig)

# # print(((ms1*y1)%curve_order))
# # print(((ms2*y2)%curve_order))
# # print(((m_dash*y3)%curve_order))

# # r = 20156700872933550759267540064638900540588652257628622225325384366766206413157
# # e = 16389790031173560773266694088120394367192792770435736281137642459488516053079
# # C = add(add(multiply(g,r), multiply(Y1,ms)),multiply(Y2,e))
# # print("Commit ")
# # print(C)

# # u = 21245716128434619676657635089542934558945080937037031944081780191751442635352

# # sign1 = multiply(g,u)
# # print("sign")
# # print(sign1)
# # sign2 = multiply(add(X,C), u)
# # print(sign2)

# # print("unblind")

# # sign2 = add(sign2,multiply(sign1,curve_order - r))
# # print(sign2)

# # temp = add(X_ti, add(multiply(Y1_ti,ms), multiply(Y2_ti, e)))
# # print("temp")
# # print(temp)
# # print(pairing(temp,sign1))
# # print("dfghjk")
# # print(pairing(g_ti, sign2))
# #print(multiply(g,b))

# # sk = random.randint(2, curve_order)
# # pk = multiply(G2, sk)
# # print(pk)
# # x1 = random.randint(2, curve_order)
# # v = multiply(G1,(x1+sk)%curve_order)
# # x2 = random.randint(2, curve_order)
# # v = multiply(v,(x2+sk)%curve_order)
# # # x2 = random.randint(2, curve_order)
# # # v = multiply(v,(x2+sk)%curve_order)
# # # x3 = random.randint(2, curve_order)
# # # v = multiply(v,(x3+sk)%curve_order)
# # # x4 = random.randint(2, curve_order)
# # print(v)
# # S = [x1, x2]
# # u = 1
# # x = random.randint(2, curve_order)
# # for i in S:
# #     u = (u * ((sk+i)%curve_order))%curve_order
# # d = 1
# # for i in S:
# #     t = (i - x)%curve_order
# #     if(t<0):
# #         t = t+curve_order
# #     d = ((d*t)%curve_order)%curve_order
# # print("u")
# # print(u)
# # print("d")
# # d = curve_order - d
# # print(d)
# # # d = u%((sk+x)%curve_order)
# # # print("d")
# # # print(d)

# # c = multiply(G1, (u+d)%curve_order)
# # c = multiply(c, (curve_order - (x+sk)%curve_order))
# # print("c")
# # print(c)
# # print(((u+d)%curve_order)%((x+sk)%curve_order))
# # # print(pairing(add(multiply(G2,x), pk),c)*pairing(G2,G1)**d)
# # # print(pairing(G2,v))
# # # print()
# # # #c = multiply()
# r = 
# s_id = 
# s_m = 
# sig1 = 
# sig1 = (FQ2(sig1[0]),FQ2(sig1[1]))
# sig2 = 
# sig2 = (FQ2(sig2[0]),FQ2(sig2[1]))
# m_d = 
# r_sig1 = multiply(sig1, r)
# r_sig2 = multiply(sig2, r)
# print("r_sig1")
# print(r_sig1)
# print("r_sig2")
# print(r_sig2)
# s_id_r_sig1 = multiply(r_sig1, s_id)
# s_m_r_sig1 = multiply(r_sig1, s_m)
# u = pairing(Y1, s_id_r_sig1) * pairing(Y3, s_m_r_sig1)
# print("u")
# print(u)
# c = 
# vid = (s_id - (c*id)%curve_order)%curve_order
# if vid<0:
#     vid = vid+curve_order
# print("vid")
# print(vid)

# vm = (s_m - (c*m_d)%curve_order)%curve_order
# if vm<0:
#     vm = vm+curve_order
# print("vm")
# print(vm)

# temp = add(multiply(X, -1), multiply(Y2,-1*epoc))
# print("temp")
# print(temp)

# pai1 = pairing(Y1,multiply(sig1, vid))
# print("pai1")
# print(pai1)

# pai2 = pairing(Y3,multiply(sig1, vm))
# print("pai2")
# print(pai2)

# pai3 = pairing(g_ti,multiply(sig2, c))
# print("pai3")
# print(pai3)

# pai4 = pairing(temp,multiply(sig1, c))
# print("pai4")
# print(pai4)

# ans = pai1*pai2*pai3*pai4
# print("ans")
# print(ans)
# print(ans == u)




