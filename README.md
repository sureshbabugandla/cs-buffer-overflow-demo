# Buffer Overflow Lab


We built four small vulnerable TCP servers in C to show different things that
can go wrong with buffer overflows, and wrote an exploit for each. For every
vulnerable server there's also a fixed version (same name with _fix) so we can
run the same attack against the fix and show it no longer works. All of it runs
locally on 127.0.0.1. Tested on Ubuntu (gcc 13).

The four demos:

| # | Server | Port | What goes wrong | What the attacker gets | Real-world case |
|---|--------|------|-----------------|------------------------|-----------------|
| 1 | server.c | 9999 | memcpy with no length check, return address overwritten | shell on the server | Morris Worm (1988) |
| 2 | leak_server.c | 9998 | buffer not null-terminated, printed with %s | reads secret data next to the buffer | Heartbleed (2014) |
| 3 | integer_server.c | 9997 | negative length passes a signed size check | overflow (size check bypassed) | Stagefright (2015) |
| 4 | dos_server.c | 9996 | unbounded copy crashes a single-process server | service goes down for everyone | Ping of Death (1996) |

They all come back to the same mistake - trusting a size or length from the
network without checking it. Each runs on its own port so we can keep them all
up at once.


## Setup

```
sudo apt install -y gcc python3
```

The exploits are plain Python (socket module), no pwntools needed, so nothing
to pip install.

Turn ASLR off before demos 1 and 3 (the addresses need to stay fixed):
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
Put it back when done: `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`

Compile the vulnerable servers:
```
gcc -g -O0 -fno-stack-protector -no-pie server.c          -o server
gcc    -O0 -fno-stack-protector         leak_server.c     -o leak_server
gcc -g -O0 -fno-stack-protector -no-pie integer_server.c  -o integer_server
gcc    -O0 -fno-stack-protector         dos_server.c      -o dos_server
```

Compile the fixed servers (protections on):
```
gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack server_fix.c         -o server_fix
gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack leak_server_fix.c    -o leak_server_fix
gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack integer_server_fix.c -o integer_server_fix
gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack dos_server_fix.c     -o dos_server_fix
```

(`bash demo_all.sh build` compiles the vulnerable ones and turns ASLR off in one
step.)


## Files

| Vulnerable | Fix | Exploit | Port |
|------------|-----|---------|------|
| server.c | server_fix.c | exploit.py | 9999 |
| leak_server.c | leak_server_fix.c | leak_exploit.py | 9998 |
| integer_server.c | integer_server_fix.c | integer_exploit.py | 9997 |
| dos_server.c | dos_server_fix.c | dos_exploit.py | 9996 |

demo_all.sh builds the vulnerable servers and can run each demo.
The servers fork a child per client (the vulnerable DoS one doesn't, on purpose).

A note on two terminals vs one: demo 1 needs two terminals because it gives you
an interactive shell to type into. Demos 2, 3, 4 just send fixed input and print
the reply, so they work fine in two terminals OR you can let `demo_all.sh` run
both ends in one terminal. The steps below use two terminals everywhere so it's
consistent.


## Demo 1 - return address overwrite

**What's the bug**

server.c reads the request into a 64-byte buffer with memcpy and no length
check. There's also a give_shell() function that hooks the client socket up to
/bin/sh. It never gets called normally - the point is to jump to it.

**How the exploit works**

exploit.py sends 88 bytes of junk + the address of give_shell(). The 88 is
64 (buffer) + 16 (padding/alignment) + 8 (saved RBP), i.e. the distance to the
saved return address. We got it from the disassembly (buffer is at -0x50 of rbp)
and it matched when we tried it. After the function returns it jumps into
give_shell() and we get a shell on the server over the same connection.

**Run the attack**

Terminal 1 (server):
```
./server
```
Terminal 2 (attacker):
```
python3 exploit.py 127.0.0.1 9999
```
You get a shell. Type `id`, `pwd`, `exit`. Nice trick: start terminal 2 from a
different folder (`cd /tmp` first) - `pwd` in the shell still shows the server's
folder, proving the shell runs on the server side, not ours.

**Run the fixed version**

Terminal 1 (server):
```
./server_fix
```
Terminal 2 (attacker):
```
python3 exploit.py 127.0.0.1 9999
```
No shell this time. The copy is bounded so the return address is never
overwritten - the exploit just gets the normal "Server received: AAAA..." reply
and the connection closes.

**Real-world example**

The Morris Worm (1988) spread by overflowing a buffer in the fingerd daemon the
same way (it used gets()).
https://en.wikipedia.org/wiki/Morris_worm

**Fix (what changed in server_fix.c)**

Bound the copy so it can't write past the buffer:
```
size_t copy = (size_t)n < sizeof(buffer)-1 ? (size_t)n : sizeof(buffer)-1;
memcpy(buffer, request, copy);
buffer[copy] = '\0';
```
Built with -fstack-protector-strong (canary), NX, PIE and RELRO on as well.


## Demo 2 - leaking data next to the buffer

**What's the bug**

leak_server.c keeps a fake "account secret" in a struct right after the input
buffer. It reads input into the buffer but doesn't add a '\0' if you send a full
32 bytes, then prints it back with %s.

**Why it leaks**

%s prints until it hits a 0 byte. If the buffer has no terminator, printf keeps
going past it into the next thing in memory - which is the secret - and sends
that back too. We used a struct so the secret is guaranteed to sit right after
the buffer (struct members stay in order).

**Run the attack**

Terminal 1 (server):
```
./leak_server
```
Terminal 2 (attacker):
```
python3 leak_exploit.py 127.0.0.1 9998
```
The 32-byte input comes back with the account string tacked on the end. Try a
short input to compare:
```
python3 -c "import socket;s=socket.create_connection(('127.0.0.1',9998));s.sendall(b'hello');print(s.recv(999))"
```
"hello" comes back clean - the leak only happens when the buffer is filled
completely (32 bytes), which is the proof it's the missing terminator.

**Run the fixed version**

Terminal 1 (server):
```
./leak_server_fix
```
Terminal 2 (attacker):
```
python3 leak_exploit.py 127.0.0.1 9998
```
Now you only get your own bytes back - no account string. The fix reserves a
byte, always terminates, and prints with %.*s, so it can't read into the secret.

**Real-world example**

Heartbleed (CVE-2014-0160). OpenSSL trusted a length the client sent without
checking how much was actually sent, read past the buffer, and leaked private
keys and passwords. Same idea, on the heap.
https://en.wikipedia.org/wiki/Heartbleed

**Fix (what changed in leak_server_fix.c)**

Leave room and always terminate, and bound the output:
```
ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
buf[n] = '\0';
dprintf(fd, "Server received: %.*s\n", (int)n, buf);
```
Also don't keep secrets right next to attacker input.


## Demo 3 - signed length bug

**What's the bug**

integer_server.c reads a length as a signed int, checks `if (len > 64) return;`,
then uses it as the size for recv. The check looks fine but recv's size argument
is unsigned (size_t).

Send len = -1: it's not greater than 64 so it passes the check, but -1 as a
size_t is a huge number (SIZE_MAX), so the copy reads way more than 64 bytes and
overflows. So the "safe" check does nothing.

| len  | passes len>64 ? | size used | result   |
|------|-----------------|-----------|----------|
| 10   | no              | 10        | fine     |
| 200  | yes -> rejected | -         | blocked  |
| -1   | no              | SIZE_MAX  | overflow |

**Run the attack**

Terminal 1 (server):
```
./integer_server
```
Terminal 2 (attacker):
```
python3 integer_exploit.py 127.0.0.1 9997
```
You'll see len=10 stored, len=200 rejected, and len=-1 give "no reply / crashed"
- that last one is the overflow firing (it crashes the child handling it).

**Run the fixed version**

Terminal 1 (server):
```
./integer_server_fix
```
Terminal 2 (attacker):
```
python3 integer_exploit.py 127.0.0.1 9997
```
Now len=-1 is rejected like len=200 - it no longer slips through, so no crash.

**Real-world example**

Stagefright on Android (CVE-2015-3864 and others, 2015). A crafted MP4 caused an
integer overflow when atom sizes were added up, so a too-small buffer got
allocated and then a memcpy overflowed it. A malicious MMS could root the phone.
~1 billion devices affected.
https://en.wikipedia.org/wiki/Stagefright_(bug)

**Fix (what changed in integer_server_fix.c)**

Check both ends of the range, which catches the negative value:
```
if (len <= 0 || len > (int)sizeof(buffer)-1) { reject; return; }
```
Compile with -Wconversion -Wsign-conversion so the compiler warns about
signed/unsigned mixups too.


## Demo 4 - crashing the service (DoS)

**What's the bug**

dos_server.c is single-process on purpose (no fork). The vulnerable copy is in a
function that returns, so an oversized request overwrites that function's return
address and the process crashes when it returns. Because there's no fork, that
one crash takes the whole service down for everyone. No crafted payload needed,
just send a lot of bytes.

(Note: an earlier version had the copy directly in main()'s loop, which did NOT
crash, because main never returns so the corrupted return address was never
used. Moving the copy into a returning function is what makes the crash happen -
a good reminder that an overflow only crashes when the corrupted data is used.)

**Run the attack**

Terminal 1 (server):
```
./dos_server
```
Terminal 2 (attacker):
```
python3 dos_exploit.py 127.0.0.1 9996
```
Watch terminal 1: after the 5000-byte blob the ./dos_server process dies and the
prompt comes back. The reconnect in the exploit then fails with "connection
refused" - the service is down.

**Run the fixed version**

Terminal 1 (server):
```
./dos_server_fix
```
Terminal 2 (attacker):
```
python3 dos_exploit.py 127.0.0.1 9996
```
The server stays up - the copy is bounded so the big blob is just truncated, and
it now forks per client so even a crash would only kill one child. The reconnect
succeeds ("still up").

**Real-world example**

Ping of Death (1996). An ICMP packet bigger than the max IP size overflowed the
reassembly buffer when the system put the fragments back together, and
crashed/rebooted the machine. No code execution, just a crash.
https://en.wikipedia.org/wiki/Ping_of_death

**Fix (what changed in dos_server_fix.c)**

Two parts: bound the copy (root cause), and fork a child per client so one crash
can't take down the whole server:
```
size_t copy = (size_t)n < sizeof(buffer) ? (size_t)n : sizeof(buffer)-1;
memcpy(buffer, staging, copy);
...
if (fork()==0) { handle_request(c); _exit(0); }   // per-client child
```
Running it under systemd with Restart=on-failure would also auto-recover it.


## Takeaway

All four come down to the same thing - trusting a size or length from the
network without checking it. The fixes are the same idea each time: bound the
copy / check the length properly, terminate strings, and build with the
protections on (canary, NX, ASLR, PIE, RELRO). And don't run services as root,
so even a successful exploit is limited.
