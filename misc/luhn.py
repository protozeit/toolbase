from ast import literal_eval

licenses = literal_eval(open("message.txt").read())
def sum_digits(n: int):
    return sum(map(int,str(n)))
def luhn(num):
    checksum =0
    num = list(map(int,num[::-1]))

    for i,n in enumerate(num):
        if i%2:
            checksum += sum_digits(n*2)

        else:
            checksum += n

    return not checksum % 10

for l in licenses:
    if luhn(l):
        print(l)
        
def test_vectors():
    for l in map(str, [79927398710, 79927398711, 79927398712, 79927398713, 79927398714, 79927398715, 79927398716, 79927398717, 79927398718, 79927398719]):
        print(l, luhn(l))

