def num_lsb(stuff):
    t = 0
    for i in range(0,len(stuff)):
        t += ord(stuff[i]) << (8 * i)
    return t

def num_msb(stuff):
    t = 0
    for i in range(0,len(stuff)):
        t = (t<<8) + ord(stuff[i])
    return t

