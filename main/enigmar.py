from math import floor
from random import randint


def creatCode():
    binaries = []
    for number in range(32):
        binaries.append(format(number, '05b'))
    return dict(zip(binaries, alphabet))


alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ.,!?:'")
code = creatCode()


def command(command, data_length, ctype):
    if ctype == 'h':
        bits_required = 5
    elif ctype == 'i':
        bits_required = 1.5

    if command == 'ALL':
        return int((data_length / bits_required))
    elif command.startswith('ALL-'):
        command = command.replace('ALL-', '')
        if int((data_length / bits_required) - int(command)) <= 0:
            return 1
        else:
            return int((data_length / bits_required) - int(command))
    else:
        if int(command) > int((data_length / bits_required)):
            return int((data_length / bits_required))
        else:
            return int(command)


def generateIndex(data, ctype, index_length):
    index_length = command(index_length, len(data), ctype)
    result = listToString([alphabet[randint(0, 31)] for _ in range(index_length)])
    return result


def readLSB(data, ctype, index_length, save_rest):
    bit_list, rest_list = [], []
    lsb_string = ""
    index_length = command(index_length, len(data), ctype)

    for data_index, data_instance in enumerate(data):
        if len(lsb_string) == index_length:
            return rest_list, lsb_string

        if save_rest:
            rest, least_significant_bit = inCode(data_instance, ctype)
            rest_list.append(rest)
        else:
            _, least_significant_bit = inCode(data_instance, ctype)

        if ctype == 'h':
            bit_list.append(least_significant_bit[0])
        elif ctype == 'i':
            bit_list.append(least_significant_bit[1])
            bit_list.append(least_significant_bit[0])

        if len(bit_list) >= 5:
            use_instead = [5, -1]
            bit_string = listToString(bit_list)[:use_instead[len(bit_list) - 5]]
            bit_list = bit_list[5:]

            lsb_string = f"{lsb_string}{code[bit_string]}"

    return rest_list, lsb_string


def getNewDisk(newdisk_in_index):
    new_disk = []
    for letter_index, letter in enumerate(newdisk_in_index):
        if letter not in new_disk:
            new_disk.append(letter)
        elif len(new_disk) == 32:
            return letter_index, listToString(new_disk)
    return letter_index, listToString(new_disk)


def cipherWithFile(data, ctype, cipher_name):
    index_list, rest = readLSB(data, ctype, 'ALL', True)
    index_string = listToString(index_list)

    if cipher_name == 'ENIGMA':
        letter_index = 0
        rotors, turnover, reflector, position, rings = [], [], [], [], []

        use_instead = [3, 4]
        how_many_rotors = use_instead[letter_index % 2]
        letter_index += 1

        while len(rotors) < how_many_rotors:
            letter_index, new_disk = getNewDisk(index_string[-(len(index_string) - letter_index + 1):])
            rotors.append(new_disk)

        while len(turnover) < len(rotors):
            if len(turnover) == 0 and len(rotors) == 4:
                turnover.append(None)
            else:
                if letter_index % 2 == 0:
                    turnover.append([alphabet.index(index_string[letter_index])])
                    letter_index += 1
                else:
                    turnover.append([alphabet.index(index_string[letter_index]), alphabet.index(index_string[letter_index + 1])])
                    letter_index += 2

        reflector = dict(zip(alphabet, alphabet))
        letter_index, new_disk = getNewDisk(index_string[-(len(index_string) - letter_index + 1):])
        new_disk = [letter for letter in new_disk if letter not in alphabet[:16]]

        for new_disk_index, letter in enumerate(new_disk):
            reflector[letter] = alphabet[new_disk_index]
            reflector[alphabet[new_disk_index]] = letter

        while len(position) < len(rotors):
            position.append(alphabet.index(index_string[letter_index]))
            letter_index += 1

        while len(rings) < len(rotors):
            rings.append(alphabet.index(index_string[letter_index]))
            letter_index += 1

        plugboard = dict(zip(alphabet, alphabet))
        #if alphabet.index(rest[letter_index]) % 32 != 0:
        if letter_index % 64 != 0:
            letter_index += 1

            letter_index, new_disk = getNewDisk(index_string[-(len(index_string) - letter_index + 1):])
            plugs = list(map(''.join, zip(*[iter(new_disk)] * 16)))
            how_many_plugs = floor(alphabet.index(index_string[letter_index]) / 2) + 1
            letter_index += 1
            for new_disk_index, letter in enumerate(plugs[0]):
                if new_disk_index == how_many_plugs:
                    break
                else:
                    plugboard[letter] = plugs[1][new_disk_index]
                    plugboard[plugs[1][new_disk_index]] = letter

        return rotors, turnover, reflector, position, rings, plugboard

    else:
        if cipher_name == 'CAESAR':
            return index_string[:1], None
        elif cipher_name == 'NEW DISK':
            _, new_disk = getNewDisk(rest)
            return index_string, new_disk
        else:
            return index_string, None


def inCode(integer, ctype):
    bits = checkBits(ctype)
    number_b2 = format(integer, f'0{bits}b').replace('-', '1')

    if len(number_b2) > bits:
        number_b2 = number_b2[1:]

    if ctype == 'h':
        least_significant_bit = [number_b2[15]]
    elif ctype == 'i':
        least_significant_bit = [number_b2[15], number_b2[31]][::-1]
        number_b2 = number_b2[0: 15:] + number_b2[15 + 1::]

    groups = list(map(''.join, zip(*[iter(number_b2)] * 5)))
    for group_index, group in enumerate(groups):
        groups[group_index] = code[group]

    return listToString(groups), least_significant_bit


def outCode(string, least_significant_bit, ctype):
    bits = checkBits(ctype)
    number_b2 = []

    for character_index, character in enumerate(string):
        number_b2.append(list(code.keys())[list(code.values()).index(character)])
        if bits == 32 and character_index == 2:
            number_b2.append(least_significant_bit[1])
    number_b2.append(least_significant_bit[0])

    number_b2 = listToString(number_b2)
    if number_b2.startswith('0'):
        return int(number_b2, 2)
    else:
        if number_b2.replace('0', '') == '1':
            if bits == 16:
                return -32768
            elif bits == 32:
                return -2147483648
        else:
            return -int(number_b2[1:], 2)


def listToString(list):
    string = ''
    return string.join(list)


def checkBits(ctype):
    if ctype == 'h':
        return 16
    elif ctype == 'i':
        return 32


def rotateDisk(disk, character):
    left = alphabet.index(character)
    return disk[left:] + disk[:left]


def nextIndex(index, index_switch):
    index += 1
    if index == index_switch:
        index = 0
    return index


class CIPHER:
    def __init__(self, integer, ctype, cipher_name, decrypting, index_encrypting, index, index_string):
        self.index = index[0]
        self.index_encrypting = index_encrypting

        string, self.least_significant_bit = inCode(integer, ctype)
        cryptogram = self.decryptor(cipher_name, decrypting, string, index_string)
        self.indexEncrypting(decrypting, index_encrypting, index[1], index_string, ctype)
        self.result = outCode(cryptogram, self.least_significant_bit, ctype)

    def resultCipher(self):
        return self.result, self.index, self.index_encrypting

    def indexEncrypting(self, decrypting, index_encrypting, data_index, index_string, ctype):
        if not decrypting and index_encrypting:
            if ctype == 'h':
                encrypted_message_index = floor((data_index / 5))
                try:
                    bit_string = list(code.keys())[list(code.values()).index(index_string[encrypted_message_index])]
                    self.least_significant_bit = bit_string[data_index % 5]
                except IndexError:
                    self.index_encrypting = False

            elif ctype == 'i':
                if data_index == 2 + 5 * floor(data_index / 5):
                    encrypted_message_index = -1 + 2 * floor(data_index / 5)

                    try:
                        bit_string_left = list(code.keys())[list(code.values()).index(index_string[encrypted_message_index])]
                        bit_string_right = list(code.keys())[list(code.values()).index(index_string[encrypted_message_index + 1])]

                        self.least_significant_bit = [bit_string_right[0], bit_string_left[4]]
                    except IndexError:

                        try:
                            bit_string_left = list(code.keys())[list(code.values()).index(index_string[encrypted_message_index])]
                            self.least_significant_bit = [self.least_significant_bit[0], bit_string_left[4]]
                        except IndexError:
                            self.index_encrypting = False

                else:
                    which_pair = [[1, 0], [3, 2], [0, 4], [2, 1], [4, 3]]
                    use_instead = {0: 0, 1: 0, 3: 1, 4: 1, 5: 2, 6: 2, 8: 3, 9: 3}
                    encrypted_message_index = use_instead[data_index % 10] + 4 * floor(data_index / 10)

                    try:
                        bit_string = list(code.keys())[list(code.values()).index(index_string[encrypted_message_index])]
                        self.least_significant_bit = [bit_string[which_pair[data_index % 5][0]], bit_string[which_pair[data_index % 5][1]]]
                    except IndexError:
                        self.index_encrypting = False

    def decryptor(self, cipher_name, decrypting, string, index_string):
        result = []

        if cipher_name == "1TO0":
            cipher = dict(zip(alphabet, alphabet[::-1]))

            for character in string:
                result.append(cipher[character])

        else:
            if cipher_name == "CAESAR" or cipher_name == "VIGENERE":
                disk = alphabet
            elif len(cipher_name) == len(alphabet):
                disk = list(cipher_name)

            if decrypting:
                for character in string:
                    self.index = nextIndex(self.index, len(index_string))

                    cipher = dict(zip(rotateDisk(disk, index_string[self.index]), disk))
                    result.append(cipher[character])
            else:
                for character in string:
                    self.index = nextIndex(self.index, len(index_string))

                    cipher = dict(zip(disk, rotateDisk(disk, index_string[self.index])))
                    result.append(cipher[character])

        return listToString(result)


def enigmaRotors():
    rotor1 = list("ZPRMD'HLKEU,GYOJI:TCNA.?FWVS!QBX")
    rotor2 = list("?HJXWVTN.LAKZF!SE:,BG'DUYQPMCORI")
    rotor3 = list("AP?NTI'.WV,RJLHXDKEZBMY!CQGS:FUO")
    rotor4 = list("BL.I:UNHQXDMTP!',AKFSGVJWO?ZYRCE")
    rotor5 = list("NYFQMPG'JUEDIHK.:BOVTW!S?,LRCAXZ")
    rotor6 = list("MY!XRWONDTSKV?IZJQUPAEBH,':.LCGF")
    rotor7 = list("R:IGZJT,FWMHBYES'UKDCXNV.LQ!AP?O")
    rotor8 = list("NWRTKMVYOEPIUDHBFQZ?!L,:CGJSAX.'")

    rotorB = list("TYGK.H?!PFZSINXJULRVODMC',AEB:QW")
    rotorG = list("RHCM'SPFBE,DNUIXK!A.LJTVYQZ?O:WG")

    return [rotorB, rotor1, rotor2, rotor3, rotor4, rotor5, rotor6, rotor7, rotor8, rotorG]


def enigmaReflectors():
    reflectorA = list("UHYPG'EBKLQJOVMDIZ.TANXWCRS!,:?F")
    reflectorB = list("'!UIX?MYDKJ:GZS,VTORCQ.EHNWPBFLA")
    reflectorC = list("OZEHCGFDQR:P'XALIJW,!YSNVB?TU.KM")
    reflectorBthin = list("WBOPC:I'KZFQ?,REDVXLGUA.!NMJYHST")
    reflectorCthin = list("IQ'FCPSMK!WXGVRDBET?OYAUJH:.LZ,N")

    return [reflectorA, reflectorB, reflectorC, reflectorBthin, reflectorCthin]


def enigmaLoop(integer):
    if integer > (len(alphabet) - 1):
        return integer - len(alphabet)
    elif integer < 0:
        return len(alphabet) + integer
    else:
        return integer


def eingmaShift(character, how_much):
    shifted = alphabet.index(character) + how_much
    return enigmaLoop(shifted)


def enigmaSwitchRepresentation(rotor):
    new_rotor = []
    for rotor_index in range(len(rotor)):
        index = alphabet.index(rotor[rotor_index])

        if rotor_index < index:
            new_rotor.append(index - rotor_index)
        else:
            new_rotor.append(-(rotor_index - index))
    return new_rotor


def enigmaSetupTurnover(rotor):
    all_turnovers = {0: None, 1: "U", 2: "F", 3: ".", 4: "L", 5: "'", 6: "P'", 7: "P'", 8: "P'", 9: None}
    turnover = all_turnovers[int(rotor)]

    if turnover is not None:
        turnover_list = list(turnover)

        for turnover_index, turnover in enumerate(turnover_list):
            turnover_list[turnover_index] = alphabet.index(turnover)

        turnover = turnover_list
    return turnover


class ENIGMA:
    def __init__(self, integer, ctype, chosen_rotors, rotor_turnover, chosen_reflector, current_position, chosen_rings, chosen_plugs):
        self.chsn_rotors_letters = chosen_rotors
        self.chsn_reflector = chosen_reflector
        self.rotor_turnover = rotor_turnover
        self.current_position = current_position
        self.chsn_rings = chosen_rings
        self.chsn_plugs = chosen_plugs

        if not self.rotor_turnover:
            self.setupEnigma()

        self.chsn_rotors = []
        for rotor in self.chsn_rotors_letters:
            self.chsn_rotors.append(enigmaSwitchRepresentation(rotor))

        string, least_significant_bit = inCode(integer, ctype)
        self.result = outCode(self.decryptorEnigma(string), least_significant_bit, ctype)

    def resultEnigma(self):
        return self.result, self.chsn_rotors_letters, self.rotor_turnover, self.chsn_reflector, self.current_position, self.chsn_rings, self.chsn_plugs

    def setupEnigma(self):
        all_reflectors = enigmaReflectors()
        self.chsn_reflector = dict(zip(alphabet, all_reflectors[self.chsn_reflector]))
        del all_reflectors

        plugboard = dict(zip(alphabet, alphabet))

        all_rotors = enigmaRotors()
        rotors, turnover, position, rings = [], [], [], []
        for rotor_index, rotor in enumerate(self.chsn_rotors_letters):
            rotors.append(all_rotors[int(rotor)])
            self.rotor_turnover.append(enigmaSetupTurnover(rotor))
            rings.append(alphabet.index(self.chsn_rings[rotor_index]))
            position.append(alphabet.index(self.current_position[rotor_index]) - rings[rotor_index])

        self.chsn_rotors_letters, self.current_position, self.chsn_rings = rotors, position, rings
        del rotors, position, rings, all_rotors

        for plug_index in range(0, 48, 3):
            if plug_index >= len(self.chsn_plugs):
                break
            else:
                plugboard[self.chsn_plugs[plug_index]] = self.chsn_plugs[plug_index + 1]
                plugboard[self.chsn_plugs[plug_index + 1]] = self.chsn_plugs[plug_index]

        self.chsn_plugs = plugboard
        del plugboard

    def rotationEnigma(self):
        if self.rotor_turnover[len(self.chsn_rotors) - 1] is not None:
            self.current_position[len(self.chsn_rotors) - 1] += 1

            for rotor_index in range(len(self.chsn_rotors) - 1, -1, -1):
                position_y = enigmaLoop(self.current_position[rotor_index] + self.chsn_rings[rotor_index])
                try:
                    position_z = enigmaLoop(self.current_position[rotor_index + 1] + self.chsn_rings[rotor_index + 1])
                except IndexError:
                    position_z = None

                if self.rotor_turnover[rotor_index] is None:
                    break
                if rotor_index == len(self.chsn_rotors) - 1 and (position_y - 1 in self.rotor_turnover[rotor_index]):
                    self.current_position[rotor_index - 1] += 1
                elif (rotor_index != len(self.chsn_rotors) - 1 and self.rotor_turnover[rotor_index - 1] is not None and rotor_index != 0) \
                        and (position_y in self.rotor_turnover[rotor_index]) and not (position_z - 1 in self.rotor_turnover[rotor_index + 1]):
                    self.current_position[rotor_index - 1] += 1
                    self.current_position[rotor_index] += 1

            for rotor_index in range(len(self.chsn_rotors)):
                self.current_position[rotor_index] = enigmaLoop(self.current_position[rotor_index])

    def decryptorEnigma(self, string):
        result = []
        for character in string:
            self.rotationEnigma()

            character = self.chsn_plugs[character]

            for rotor_index, rotor in enumerate(self.chsn_rotors[::-1], 1 - len(self.chsn_rotors)):
                character = alphabet[eingmaShift(character, rotor[eingmaShift(character, self.current_position[-rotor_index])])]

            character = self.chsn_reflector[character]

            for rotor_index, rotor in enumerate(self.chsn_rotors):
                character = alphabet[eingmaShift(character, -rotor[self.chsn_rotors_letters[rotor_index].index(alphabet[eingmaShift(character, self.current_position[rotor_index])])])]

            character = self.chsn_plugs[character]

            result.append(character)
        return listToString(result)


#print(ENIGMA(0, 'h', '321', [], 1, 'KDO', 'AAA', '').result)
#print(ENIGMA(-7332, 'h', '321', [], 1, 'KDO', 'AAA', '').result)

#print(CIPHER(0, 'h', "1TO0", False, False, [-1, 0], 'ABC').result)
#print(CIPHER(0, 'h', "CAESAR", False, False, [-1, 0], 'C').result)
#print(CIPHER(0, 'h', "VIGENERE", False, False, [-1, 0], 'ABC').result)
#print(CIPHER(0, 'h', "A:M?IC'ZGPRWHFE.OVYBQN!KDUTS,JLX", False, False, [-1, 0], 'ABC').result)
#print(ENIGMA(0, 'h', '321', [], 1, 'ABC', 'CBA', 'AB').result)

#n = 8
#all_rotors = enigmaRotors()
#all_reflectors = enigmaReflectors()
#print(enigmaSwitchRepresentation(all_rotors[n]))
#print(len(set(all_rotors[n])))


#data = []
#for _ in range(1000):
#    data.append(0)
#gen = generateIndex(data, 'h', '100')
#print(getNewDisk(gen))


#alpha = "VIGENERE"
#alpha = "UHYPG'EBKLIJOVMDTZ.QANXWCRS!,:?F"

#a = CIPHER(0, 'h', alpha, False, False, [-1, 0], 'PLZ').result
#c = CIPHER(a, 'h', alpha, False, False, [-1, 0], 'DAS').result
#b = CIPHER(0, 'h', alpha, False, False, [-1, 0], 'GAZ').result
#d = CIPHER(b, 'h', alpha, False, False, [-1, 0], 'JEW').result

#a2 = CIPHER(d, 'h', alpha, False, False, [-1, 0], 'PLZ').result
#c2 = CIPHER(a2, 'h', alpha, False, False, [-1, 0], 'DAS').result
#b2 = CIPHER(c, 'h', alpha, False, False, [-1, 0], 'GAZ').result
#d2 = CIPHER(b2, 'h', alpha, False, False, [-1, 0], 'JEW').result
#print(c2, d2)

#h_ac = CIPHER(d, 'h', alpha, False, False, [-1, 0], inCode(c, 'h')[0]).result
#h_bd = CIPHER(c, 'h', alpha, False, False, [-1, 0], inCode(d, 'h')[0]).result
#print(h_ac, h_bd)
