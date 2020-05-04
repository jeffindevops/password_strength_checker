
import crypt


password = 'test'

sha = '$6$hPtvx736$qVJGkRdn9ZEsCfmpLjjC8G.xsnhlXjJIEntGooUVtqvIIui5u028u8Ts5j9ur7Rz1ibn.1h.UAMZfiTCGhfCk.'

salt = '$6$hPtvx736'

c_pass = crypt.crypt(password,salt)

if c_pass == sha:
    print 'Password matched'
else:
    print 'Password Not matched'
