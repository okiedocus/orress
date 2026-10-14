SECRET = "flag{n0t_a_r3al_flag}"

def check(pw):
    total = 0
    for i, c in enumerate(pw):
        total += ord(c) ^ (i + 7)
    return total == 1337

def main():
    print("enter password:")
