import re

def range_exp(i1, i2):
    if i1 < 0 or i1 > 999 or i2 < 0 or i2 > 999 or i1 > i2:
        return "INTERNAL ERROR"
    if i1 == i2:
        return str(i1)
    if i2 >= 255:
        i2 = 299
    if i1 < 10:
        if i2 < 10:
            if i1 == 0 and i2 == 9:
                return "\\d"
            if i2 - i1 == 1:
                return "[" + str(i1) + str(i2) + "]"
            return "[" + str(i1) + "-" + str(i2) + "]"
        elif i2 < 100:
            i2_ones = i2 % 10
            i2_tens = (i2 - i2_ones) // 10
            if i1 == 0 and i2_ones == 9:
                return range_exp(1, i2_tens) + "?\\d"
            if i1 == 0:
                return range_exp(i1, i2_tens * 10 - 1) + "|" + range_exp(i2_tens * 10, i2)
            return range_exp(i1, 9) + "|" + range_exp(10, i2)
        else:
            return range_exp(i1, 99) + "|" + range_exp(100, i2)
    elif i1 < 100:
        i1_ones = i1 % 10
        i1_tens = (i1 - i1_ones) // 10
        if i2 < 100:
            i2_ones = i2 % 10
            i2_tens = (i2 - i2_ones) // 10
            if i1_tens == i2_tens:
                return str(i1_tens) + range_exp(i1_ones, i2_ones)
            if i1_ones == 0 and i2_ones == 9:
                return range_exp(i1_tens, i2_tens) + "\\d"
            if i1_ones == 0:
                return range_exp(i1, i2_tens * 10 - 1) + "|" + range_exp(i2_tens * 10, i2)
            return range_exp(i1, (i1_tens + 1) * 10 - 1) + "|" + range_exp((i1_tens + 1) * 10, i2)
        else:
            return range_exp(i1, 99) + "|" + range_exp(100, i2)
    else:
        i1_ones = i1 % 10
        i1_tens = (i1 - i1_ones) // 10 % 10
        i1_huns = (i1 - (i1_tens * 10) - i1_ones) // 100
        i2_ones = i2 % 10
        i2_tens = (i2 - i2_ones) // 10 % 10
        i2_huns = (i2 - (i2_tens * 10) - i2_ones) // 100
        if i1_huns == i2_huns and i1_tens == i2_tens:
            return str(i1_huns) + str(i1_tens) + range_exp(i1_ones, i2_ones)
        if i1_huns == i2_huns and i1_ones == 0 and i2_ones == 9:
            return str(i1_huns) + range_exp(i1_tens, i2_tens) + "\\d"
        if i1_huns == i2_huns and i1_ones == 0:
            return range_exp(i1, (i1_huns * 100) + ((i2_tens - 1) * 10) + 9) + "|" + range_exp((i2_huns * 100) + (i2_tens * 10), i2)
        if i1_huns == i2_huns:
            return range_exp(i1, (i1_huns * 100) + (i1_tens * 10) + 9) + "|" + range_exp((i2_huns * 100) + ((i1_tens + 1) * 10), i2)
        if i1_tens == 0 and i1_ones == 0 and i2_tens == 9 and i2_ones == 9:
            return range_exp(i1_huns, i2_huns) + "\\d\\d"
        if i1_tens == 0 and i1_ones == 0:
            return range_exp(i1, (i2_huns - 1) * 100 + 99) + "|" + range_exp(i2_huns * 100, i2)
        return range_exp(i1, i1_huns * 100 + 99) + "|" + range_exp((i1_huns + 1) * 100, i2)

def ip2int(ip):
    return sum(int(octet) << (8 * i) for i, octet in enumerate(ip.split('.')[::-1])) & 0xFFFFFFFF

def is_ip(ip):
    return bool(re.match(r'^(([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.){3}([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])$', ip))

def paren(exp):
    if '|' in exp:
        return "(" + exp + ")"
    return exp

def slim(group):
    if len(group) < 3:
        return group
    slimgroup = group.copy()
    count = 0
    found = 0
    for i in range(len(slimgroup)):
        while i < len(slimgroup) and slimgroup[i] == slimgroup[i+1]:
            found = i
            count += 1
            slimgroup.pop(i)
        if count > 0:
            break
    if count > 0:
        if len(slimgroup) == 1:
            slimgroup.append("){" + str(count) + "}" + slimgroup[0])
            slimgroup[0] = "(" + slimgroup[0]
            return slimgroup
        if found == 0:
            slimgroup[0] = "(" + slimgroup[0]
            slimgroup[1] = "){" + str(count + 1) + "}" + slimgroup[1]
            return slimgroup
        slimgroup[found] = slimgroup[found] + "){" + str(count + 1) + "}"
        slimgroup[found - 1] = slimgroup[found - 1] + "("
        return slimgroup
    return group

def range_to_regex(ip1, ip2=None):
    if not is_ip(ip1):
        return "Invalid IP Address: " + ip1
    if not ip2:
        ip2 = ip1
    elif not is_ip(ip2):
        return "Invalid IP Address: " + ip2
    if ip2int(ip1) > ip2int(ip2):
        tmp = ip2
        ip2 = ip1
        ip1 = tmp
    octets1 = list(map(int, ip1.split(".")))
    octets2 = list(map(int, ip2.split(".")))
    same = []
    expression = "^"
    while octets1 and octets2:
        if octets1[0] != octets2[0]:
            break
        same.append(str(octets1.pop(0)))
        octets2.pop(0)
    expression += "\.".join(same)
    if 0 < len(same) < 4:
        expression += "\."
    case = len(octets1)
    if case == 0:
        expression += "$"
        return expression
    if case == 1:
        group = paren(range_exp(octets1[0], octets2[0]))
        return expression + group + "$"
    octets1.reverse()
    octets2.reverse()
    groups = []
    from_, to = None, None
    while True:
        found = -1
        group = []
        for index, octet in enumerate(octets1):
            if found > -1:
                group.insert(0, octet)
            elif index == len(octets1) - 1:
                from_ = octet
            elif octet == 0:
                group.insert(0, paren(range_exp(0, 255)))
            else:
                found = index
                group.insert(0, paren(range_exp(octet, 255)))
        if found == -1:
            break
        groups.append(".".join(slim(group)))
        octets1[found] = 0
        octets1[found + 1] += 1
        while octets1[found + 1] > 255:
            octets1[found + 1] = 0
            found += 1
            octets1[found + 1] += 1
    i = 0
    while True:
        found = -1
        group = []
        for index, octet in enumerate(octets2):
            if found > -1:
                group.insert(0, octet)
            elif index == len(octets1) - 1:
                to = octet
            elif octet == 255:
                group.insert(0, paren(range_exp(0, 255)))
            else:
                found = index
                group.insert(0, paren(range_exp(0, octet)))
        if found == -1:
            break
        groups.append(".".join(slim(group)))
        octets2[found] = 255
        octets2[found + 1] -= 1
        while octets2[found + 1] < 0:
            octets2[found + 1] = 255
            found += 1
            octets2[found +  1] -= 1
    if from_ <= to:
        group = []
        for i in range(len(octets1) - 1):
            group.append(paren(range_exp(0, 255)))
        group.insert(0, paren(range_exp(from_, to)))
        groups.append(".".join(slim(group)))
    end = "$"
    if len(groups) > 1:
        expression += "("
        end = ")$"
    return expression + "|".join(groups) + end

def display_regex(ip1, ip2):
    return range_to_regex(ip1, ip2)