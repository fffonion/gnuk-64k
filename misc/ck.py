def coordinate(x,y):
    return (y*5+x)

rho = [ 0 for x in range(0,25) ]

print("s[0] <= s[0]")
x = 1
y = 0
for i in range(0,24):
    print(i)
    shift = ((i+1)*(i+2)//2)%64
    print("s[",end='')
    print(coordinate(x,y),end='')
    print("] = rot(s[",end='')
    print(coordinate(x,y),end='')
    print("],",end='')
    print(shift,end='')
    print("]")
    rho[coordinate(x,y)] = shift
    (x,y) = (y,(2*x+3*y)%5)

for i in range(0,25):
    print(rho[i], end=', ')
