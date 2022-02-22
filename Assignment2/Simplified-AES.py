# SBox 
SBoxInput = ["0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"]
SBoxOutput = ["1001", "0100", "1010", "1011", "1101", "0001", "1000", "0101", "0110", "0010", "0000", "0011", "1100", "1110", "1111", "0111"]

# Encryption MixColumns Converter
EnConverter1 = [[0, 6], [1, 4, 7], [2, 4, 5], [3, 5]]
EnConverter2 = [[2, 4], [0, 3, 5], [0, 1, 6], [1, 7]]

# Decryption MixColumns Converter
DeConverter1 = [[0, 0, 3, 5], [0, 1, 1, 6], [1, 2, 2, 4, 7], [2, 3, 4]]
DeConverter2 = [[1, 4, 4], [2, 4, 5, 5], [0, 3, 5, 6, 6, 7], [0, 6, 7]]

def SplitInLength(key, length):
    return [key[i:i+length] for i in range(0, len(key), length)]

def RotNib(before):
    key = SplitInLength(before, 4)    
    after = key[1]+key[0]
    return after

# Nibble Substitution for Encryption
def SubNibEn(before):
    key = SplitInLength(before, 4)
    for index, fragment in enumerate(key):
        for Sidx, SIn in enumerate(SBoxInput):
            if fragment == SIn:
                key[index] = SBoxOutput[Sidx]
    after = "".join(key)
    return after

def XOR(k1, k2):
    k1 = list(k1)
    k2 = list(k2)
    for i in range(len(k1)):
        if k1[i] is k2[i]:
            k1[i] = "0"
        else:
            k1[i] = "1"
    k1 = "".join(k1)
    return k1
            
def KeySchedule(originalkey):
    key = originalkey.split()
    
    W0 = key[0] + key[1]
    W1 = key[2] + key[3]
    W2 = XOR(W0, XOR("10000000", SubNibEn(RotNib(W1))))
    W3 = XOR(W1, W2)
    W4 = XOR(W2, XOR("00110000",SubNibEn(RotNib(W3))))
    W5 = XOR(W3, W4)
    
    K0 = W0 + W1
    K1 = W2 + W3
    K2 = W4 + W5
    Key = [K0, K1, K2]
    return Key

# For debugging, display like a matrix
def MatrixDisplay(original):
    matrix = SplitInLength(original, 4)
    print(matrix[0], matrix[2])
    print(matrix[1], matrix[3])
    
def ShiftRow(original):
    matrix = SplitInLength(original, 4)
    matrix[1], matrix[3] = matrix[3], matrix[1]
    return "".join(matrix)

# Encryption MixColumns Multiply
def EnMultiply(converter, matrix):
    multiplied = []
    for coefblock in converter:
        converting = []
        for coef in coefblock:
            converting.append(matrix[coef])
        multiplied.append(converting)
    return MCXOR(multiplied)

def MCXOR(multiplied):
    coefficientlist = []
    for coef in multiplied:
        idx = 0
        while idx < len(coef)-1:
            if coef[idx] == coef[idx+1]:
                coef[idx+1] = "0"
            else:
                coef[idx+1] = "1"
            idx += 1
        coefficientlist.append(coef[-1])
    return "".join(coefficientlist)

def MixColumns(converter1, converter2, original):
    matrix = SplitInLength(original, 8)   
    b = matrix[0]
    c = matrix[1]
    return "".join([EnMultiply(converter1, b), EnMultiply(converter2, b), EnMultiply(converter1, c), EnMultiply(converter2, c)])
    
def Encryption(PlainText, Key):
    print()
    print("Encryption : ")
    PlainText = PlainText.replace(" ", "")

    print("AK0 :")
    AK0 = XOR(Key[0], PlainText)
    MatrixDisplay(AK0)
    print("NS1 :")
    NS1 = SubNibEn(AK0)
    MatrixDisplay(NS1)
    print("SR1 :")
    SR1 = ShiftRow(NS1)
    MatrixDisplay(SR1)
    print("Round1 :")
    Round1 = MixColumns(EnConverter1, EnConverter2, SR1)
    MatrixDisplay(Round1)
    print("AK1 :")
    AK1 = XOR(Key[1], Round1)
    MatrixDisplay(AK1)
    print("NS2 :")
    NS2 = SubNibEn(AK1)
    MatrixDisplay(NS2)
    print("SR2 :")
    SR2 = ShiftRow(NS2)
    MatrixDisplay(SR2)
    print("AK2 :")
    Ciphertext = XOR(Key[2], SR2)
    MatrixDisplay(Ciphertext)
    return Ciphertext

# Nibble Substitution for Decryption
def SubNibDe(before):
    key = SplitInLength(before, 4)
    for index, fragment in enumerate(key):
        for Sidx, SOut in enumerate(SBoxOutput):
            if fragment == SOut:
                key[index] = SBoxInput[Sidx]
    after = "".join(key)
    return after

def Decryption(CipherText, Key):
    print() 
    print("Decryprion : ")
    CipherText = CipherText.replace(" ", "")
    print("AK2 :")
    AK2 = XOR(Key[2], CipherText)
    MatrixDisplay(AK2)
    print("SR1 :")
    SR1 = ShiftRow(AK2)
    MatrixDisplay(SR1)
    NS1 = SubNibDe(SR1)
    print("NS1 :")
    MatrixDisplay(NS1)
    print("Round1 :")
    Round1 = XOR(Key[1], NS1)
    MatrixDisplay(Round1)
    print("MC :")
    MC = MixColumns(DeConverter1, DeConverter2, Round1)
    MatrixDisplay(MC)
    print("SR2 :")
    SR2 = ShiftRow(MC) 
    MatrixDisplay(SR2)
    print("NS2 :")
    NS2 = SubNibDe(SR2)
    MatrixDisplay(NS2)
    print("AK0 :")
    Decrypted = XOR(Key[0], NS2)
    MatrixDisplay(Decrypted)
    return Decrypted


def main():
# Test data
    PlainText = "0110 1111 0110 1011"
    OriginalKey = "1010 0111 0011 1011"

    print("PlainText:", PlainText)
    print("OriginalKey:", OriginalKey)
    
    # Key Schedule
    Key = KeySchedule(OriginalKey)
    
    # Encryption
    CipherText = Encryption(PlainText, Key)
    CipherText = " ".join(SplitInLength(CipherText, 4))
    print("CipherText:", CipherText)

    # Decryption
    Decrypted = Decryption(CipherText, Key)
    Decrypted = " ".join(SplitInLength(Decrypted, 4))
    print("Decrypted:", Decrypted)
    
    
if __name__ == "__main__":
    main()
