from pyasn1.codec.der import encoder
from pyasn1.type import univ, char, tag

def fill_sequence(seq, *vals):
    for i in range(len(vals)):
        seq.setComponentByPosition(i, vals[i])

class SequenceImplicitlyTagged0(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

class UTF8StringTagged0(char.GeneralString):
    tagSet = char.UTF8String.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

id_msupn_san = univ.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3')

name = UTF8StringTagged0("john.doe@EXAMPLE.COM")

san = SequenceImplicitlyTagged0()
fill_sequence(san, id_msupn_san, name)

all_san = univ.Sequence()
fill_sequence(all_san, san)

with open("msupn.der", "wb") as outfile:
    outfile.write(encoder.encode(all_san))
