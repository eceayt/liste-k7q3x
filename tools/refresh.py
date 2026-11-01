# Re-encrypts the wishlist snapshot inside index.html.
# Usage: python3 tools/refresh.py <db_dump_dir> <password>
import json,glob,os,sys,datetime,re,base64,secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
dbdir,pw=sys.argv[1:3]
here=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
page=os.path.join(here,"index.html")
K=["name","cat","stage","prio","qty","price","was","deal","est","shop","link","note","alt","img","unavailable","checkedAt","order"]
items=[]
for f in glob.glob(os.path.join(dbdir,"items","*.json")):
    d=json.load(open(f)); it={k:d.get(k) for k in K if k in d}; it["id"]=os.path.basename(f)[:-5]
    if not str(it.get("img") or "").startswith("data:image/"): it.pop("img",None)
    items.append(it)
assert items, "no items found in "+dbdir
claims=[{"id":os.path.basename(f)[:-5],"item":d.get("item"),"qty":d.get("qty",1),"self":bool(d.get("self")),"kind":"self" if d.get("self") else "gift"} for f in glob.glob(os.path.join(dbdir,"claims","*.json")) for d in [json.load(open(f))]]
meta={}
mp=os.path.join(dbdir,"meta","settings.json")
if os.path.exists(mp):
    m=json.load(open(mp)); meta={k:m.get(k) for k in ("title","due","note") if m.get(k)}
snap={"items":items,"claims":claims,"meta":meta,"updated":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
salt=secrets.token_bytes(16);iv=secrets.token_bytes(12);n=200000
key=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=n).derive(pw.encode())
ct=AESGCM(key).encrypt(iv,json.dumps(snap,separators=(",",":")).encode(),None)
b=lambda x:base64.b64encode(x).decode()
enc=json.dumps({"s":b(salt),"iv":b(iv),"n":n,"d":b(ct)})
h=open(page).read()
h,c=re.subn(r'<script id="snapenc" type="application/json">.*?</script>',lambda m:'<script id="snapenc" type="application/json">'+enc+'</script>',h,count=1,flags=re.S)
assert c==1
open(page,"w").write(h); print(len(items),"items",len(claims),"claims",len(h)//1024,"KB")
