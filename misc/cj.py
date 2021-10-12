def coordinate(x,y):
    return (y*5+x)

for y in range(0,5):
    for x in range(0,5):
        p = coordinate(x,y)
        print("s[",end='')
        print(p,end='')
        print("] = s[",end='')
        print(coordinate((x+3*y)%5,x),end='')
        print("]")
