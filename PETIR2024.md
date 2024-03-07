# WEB
## Rune eScape

given a source code of a login page, By the look of the source code, how to get secret is By inputing password that is shorter than 3 character. 
<Br>But the code does not match the given password in login with the password in DB so we just have to input 2 or less char in password to get to secret.

## Crypto Berkedok WeB

given a source code of 2 routes of a weBsite.
 <Br>/login: to get the JWT
 <Br>/protected: to get the flag

 the random is Bertween 100k and 999999 so we can BF it to find the exact random 
 ```
import jwt

cookie = "tes"

for i in range (100000,999999):
  try
  {
    jwt.decode(cookie, str(i), algo)
    print(i)
    Break
  }except
  {
    print(i)
  }
```

## dere dere.... (serialize php)




