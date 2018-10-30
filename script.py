from sha1 import Sha1Hash
import struct


# convert the number n into a string that contains the binary representation of the 64-bit number that equals n

def generate_padding(message):
    m = message
    m += b'\x80'
    # add zeros until 448
    while (len(m) * 8) % 512 != 448:
        m += b'\x00'

    # add the length of the message
    l = len(message) * 8
    m += struct.pack('>Q', l)

    return m


def main():
    M0 = 'comment=moneytransference&bankaccount=658234&userid=32167&amount=50'
    H0 = 0xded8ae96cc391112e7d341167c6a924d07896d13

    new_amount = '&amount=3000'

    H1 = "5b60303e711992c5a2f4203f71406a15699c8b65"

    # string encoding
    M0 = M0.encode()

    # add pad to the message
    message_pad = generate_padding(M0)

    # length of original message with padding
    new_len = len(message_pad)

    # add new message to the original and the calculated padding
    message_pad += new_amount.encode()
    # add final padding
    message_pad = generate_padding(message_pad)

    # delete length of the original message and the calculated padding
    final_message = message_pad
    # message_pad now contains only the new message and the relative padding
    message_pad = message_pad[new_len:]

    # get the internal state
    h = get_modified_IV(H0)

    # hash function with the internal state
    my_sha = Sha1Hash(h0=h[0], h1=h[1], h2=h[2], h3=h[3], h4=h[4])
    # compute final hash
    final_hash = my_sha.update(message_pad).hexdigest()

    # check if the generated hash is equal to the correct one
    if H1 == final_hash:
        print "Final message: " + final_message


def get_modified_IV(hash):
    # internal state of the message digest
    h0 = hash >> 128
    h1 = (hash >> 96) & 0xffffffff
    h2 = (hash >> 64) & 0xffffffff
    h3 = (hash >> 32) & 0xffffffff
    h4 = hash & 0xffffffff

    return [h0, h1, h2, h3, h4]


if __name__ == "__main__":
    main()
