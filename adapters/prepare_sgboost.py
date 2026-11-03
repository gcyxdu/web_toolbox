from pathlib import Path
import struct,zipfile,json
root=Path(__file__).resolve().parents[1]
source=root/'modules/SGBoost-main/SGBoost.jar'
target=root/'.runtime/SGBoost-local.jar'
replacement=str(root/'modules/SGBoost-main').replace('\\','/').encode()
def patch(data):
 out=bytearray(data[:10]); count=int.from_bytes(data[8:10],'big');pos=10;i=1
 while i<count:
  tag=data[pos];pos+=1;out.append(tag)
  if tag==1:
   size=int.from_bytes(data[pos:pos+2],'big');pos+=2;value=data[pos:pos+size];pos+=size
   value=value.replace(b'/SGBoost',replacement)
   out.extend(len(value).to_bytes(2,'big'));out.extend(value)
  else:
   sizes={3:4,4:4,5:8,6:8,7:2,8:2,9:4,10:4,11:4,12:4,15:3,16:2,17:4,18:4,19:2,20:2}
   size=sizes[tag];out.extend(data[pos:pos+size]);pos+=size
   if tag in (5,6):i+=1
  i+=1
 out.extend(data[pos:]);return bytes(out)
with zipfile.ZipFile(source) as src,zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as dst:
 for info in src.infolist():
  content=src.read(info.filename)
  if info.filename in ['dataowner/DataOrganizer.class','dataowner/DataOwner.class','user/user.class']: content=patch(content)
  dst.writestr(info,content)
print('Created local-path JAR; original unchanged.')
