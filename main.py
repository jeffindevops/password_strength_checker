import time
import crypt
from itertools import product

from parser import parse_options



### envs ###
max_lookup = 4
alphabets_l = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
alphabets_u = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

alphabets = alphabets_l+alphabets_u+numbers
### envs ###

def get_users(f_path):
    """
    Getting user name and password hash from file
    """
    out = {}
    with open(f_path) as file:
        for d in file:
            h = d.split(':')[1]
            if h != '*':
                u =  str(d.split(':')[0]).strip()
                if len(u) > 0:
                    out[u] = h

        return out

def check_hash(p,s,sha):
    """
    Checking the password with given sha with crypt
    """
    c_pass = crypt.crypt(p,s)
    if c_pass == sha:
        return 1
    else:
        return 0

def do_check(user,sha):
    # print user
    print time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    al = sha.split('$')[1].strip()
    s_v = sha.split('$')[2].strip()
    salt = "$"+al+"$"+s_v

    for p in range(max_lookup+1):
        print 'Looking on '+user+' serious :- '+str(p)

        comps = comp(p)
        c_f = 0
        for c in comps:
            if check_hash(c,salt,sha):
                print '##############################################'
                print 'Password matched :- %s-->%s'%(user,c)
                print '##############################################'
                c_f = 1
                g_out[user]=c
                break
        if c_f == 1:
            break

def main():
    parser, options, arguments = parse_options()

    if options.file == None:
        print 'Please provide file path'
        exit()
    else:
        users = get_users(options.file)

    for u in users:
        do_check(u,users[u])



if __name__ == '__main__':
    main()
