from gmssl import sm3,func

#消息扩展
#对消息进行填充
#将真实消息后按二进制填上1，16进制表现为0x80，最后在末尾填上消息长度
def padding(mess):
    len1 = len(mess)
    messcut = len1 % 64#将消息限制在64字节以内
    #消息后面加上1，16进制表现为0x80
    mess.append(0x80)
    #留出8字节写消息长度
    for i in range(messcut+1, 56):
         mess.append(0x00)
    length = len1 * 8#字节长度*8=比特
    bit_length_str = [length % 0x100]
    for i in range(7):
        length = int(length / 0x100)
        bit_length_str.append(length % 0x100)
    for i in range(8):
        mess.append(bit_length_str[7 - i])
    return mess

#将哈希作为消息
def hashasmess(hash):
    res = []
    for i in range(8):
        res.append(int(hash[i*8:(i+1)*8],16))
    return res

def attackfunction(mess,realhashvalue,extension):#真实消息，真实哈希值，附加的消息
    fakemess = padding(func.bytes_to_list(bytes(mess,encoding='utf-8')))
    mid = round(len(fakemess) / 64)
    fakemess += func.bytes_to_list(bytes(extension, encoding='utf-8'))
    fakemess = padding(fakemess)
    end = round(len(fakemess) / 64)
    A = []
    for i in range(mid, end):
        A.append(fakemess[i * 64:(i + 1) * 64])

    # 把原来的哈希值在进行一次压缩函数的数学运算
    B = []
    hasham= hashasmess(realhashvalue)#把原来的哈希值在进行一次压缩函数的数学运算
    B.append(hasham)
    for i in range(0, end - mid):
        B.append(sm3.sm3_cf(B[i], A[i]))
    y = B[i + 1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result
#对消息进行填充
#将真实消息后按二进制填上1，16进制表现为0x80，最后在末尾填上消息长度





mess = "AAAAAAAA"
hashvalue = sm3.sm3_hash(func.bytes_to_list(bytes(mess,encoding='utf-8')))
print('AAAAAAAA的哈希值：\n'+hashvalue)


message_extension = 'BBBBB'#添加在填充消息之后的值
mess_padding = padding(func.bytes_to_list(bytes(mess,encoding='utf-8'))) +func.bytes_to_list(bytes(message_extension,encoding='utf-8'))

messstr=str(func.list_to_bytes(mess_padding))
#for i in messstr:
 #   print(i+" ",end="")
#messstr.replace("0x00"," ")
print('假消息: \n' + messstr)

new_hashvalue = sm3.sm3_hash(mess_padding)#将填充后的消息哈希

print('填充后的哈希值 \n: '+new_hashvalue)
print('假消息的哈希值\n : '+attackfunction(mess,hashvalue,message_extension))

if new_hashvalue == attackfunction(mess,hashvalue,message_extension):
    print('success!')
else:
    print('failure!')

