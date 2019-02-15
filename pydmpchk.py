import sys
import os
import struct
import datetime
scriptname = os.path.split(sys.argv[0])[1]
if (len(sys.argv) != 2 ):
        sys.exit("usage python %s path_to_dump" % scriptname)
fin = open(sys.argv[1],'rb')
if( fin.read(4) != 'MDMP' ):
        fin.close()
        sys.exit("not a windbg dump file no  MDMP signature")
print ("Dumping Handle Information From Raw Handle Stream")
print ( "MINIDUMP_HEADER EXCLUDING SIGNATURE") 
dmphdr = struct.unpack("<HHiiiiQ",fin.read(28))
#print ( "%-20s\t0x%x") % ( "version", dmphdr[0] )
#print ( "%-20s\t0x%x") % ( "internal version", dmphdr[1] )
#print ( "%-20s\t0x%x") % ( "Number of Streams", dmphdr[2] )
#print ( "%-20s\t0x%x") % ( "Stream Directory RVA", dmphdr[3] )
#print ( "%-20s\t0x%x") % ( "CheckSum", dmphdr[4] )
#print ( "%-20s\t")     % ( "u.TimeDateStamp" ),
#print ( datetime.datetime.fromtimestamp(dmphdr[5]))
#print ( "%-20s\t0x%x") % ( "Flags", dmphdr[6] )
print ("MINIDUMP_DIRECTORY ")
#print ("%-24s%-24s%-24s") % ("StreamType" , "DataSize","RVA")
streamdata = []
for i in range(0,dmphdr[2],1):
    streamdata.insert(i,struct.unpack("<iii",fin.read(12)))
#    print ("%-24s%-24s%-24s") % ( hex(streamdata[i][0]),
#                    hex(streamdata[i][1]),hex(streamdata[i][2]))    
HStreamLoc, = [z for (x,y,z) in streamdata if x == 0xc]
HStreamDSize, = [y for (x,y,z) in streamdata if x == 0xc]
fin.seek(HStreamLoc)
sizeof_HDStream = 16 
HDStream = struct.unpack("<iiii",fin.read(sizeof_HDStream))
assert (HDStream[1] * HDStream[2] + sizeof_HDStream ) == HStreamDSize
print ("_MINIDUMP_HANDLE_DESCRIPTOR2")
sizeof_MHDesc2 = 40
HDesc = []
#print ("%-14s%-14s%-14s%-14s%-14s%-14s%-14s%-14s%-14s") % ("Handle" ,"TypeNameRva",
#    "ObjectNameRva","Attributes","GrantedAccess","HandleCount","PointerCount",
#                                                "ObjectInfoRva","Reserved0")
for i in range(0,HDStream[2],1):
    HDesc.insert(i,struct.unpack("<Qiiiiiiii",fin.read(sizeof_MHDesc2)))
#    print ("%-14s%-14s%-14s%-14s%-14s%-14s%-14s%-14s%-14s") % ( hex(HDesc[i][0]), 
#    hex(HDesc[i][1]), hex(HDesc[i][2]), hex(HDesc[i][3]),hex(HDesc[i][4]),
#    hex(HDesc[i][5]), hex(HDesc[i][6]),hex(HDesc[i][7]), hex(HDesc[i][8]))

tnbuf = []
tnindx  = 0
TNRVA = [b for (a,b,c,d,e,f,g,h,i) in HDesc ]
for i in TNRVA:
    if(i != 0 ):
        fin.seek(i)
        lent,= struct.unpack("<i" , fin.read(4))
        fmt = "<%ds" % lent 
        tname, = struct.unpack(fmt , fin.read(lent))
        tnbuf.insert( tnindx ,tname)
        tnindx += 1
    
onbuf = []
onindx  = 0    
ONRVA = [c for (a,b,c,d,e,f,g,h,i) in HDesc ]
for i in ONRVA:
    if(i != 0 ):
        fin.seek(i)
        lent,= struct.unpack("<i" , fin.read(4))
        fmt = "<%ds" % lent 
        oname, = struct.unpack(fmt , fin.read(lent))
        onbuf.insert( onindx ,oname)
        onindx += 1
    else:
        onbuf.insert( onindx ,"N\x00o\x00 \x00O\x00b\x00j\x00N\x00a\x00m\x00e\x00")
        onindx += 1
        
assert(len(onbuf) == len(tnbuf))

print (("%s%-8s%-16s%s")%("_MINIDUMP_STRING\n","Handle","TypeName","ObjectName"))
for i in range(0,len(onbuf),1):
    print (("%-8s%-16s%s") % ( hex(HDesc[i][0]) , tnbuf[i][::2], onbuf[i][::2]))
    