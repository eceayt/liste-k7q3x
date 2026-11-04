# Re-encrypts the wishlist snapshot inside index.html.
# Usage:
#   python3 tools/refresh.py <db_dump_dir> <password>          (folder of items/claims/meta JSON files)
#   python3 tools/refresh.py --compact <snap.json> <password>  (one JSON file: {"items":[...],"claims":[...],"meta":{...}})
# In --compact mode an item without "img" keeps the photo it had in the current page.
import json,glob,os,sys,datetime,re,base64,secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
here=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
page=os.path.join(here,"index.html")
K=["name","cat","stage","prio","qty","price","was","deal","est","shop","link","note","alt","img","unavailable","checkedAt","order"]
def kdf(pw,salt,n): return PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=n).derive(pw.encode())
h=open(page).read()
m=re.search(r'<script id="snapenc" type="application/json">(.*?)</script>',h,re.S); assert m
def clean_claim(c,cid=None):
    return {"id":c.get("id",cid),"item":c.get("item"),"qty":c.get("qty",1),"self":bool(c.get("self")),"kind":"self" if c.get("self") else "gift"}
if sys.argv[1]=="--compact":
    src,pw=sys.argv[2:4]
    old=json.loads(m.group(1)); b=base64.b64decode
    prev=json.loads(AESGCM(kdf(pw,b(old["s"]),old["n"])).decrypt(b(old["iv"]),b(old["d"]),None))
    oldimg={i["id"]:i.get("img") for i in prev.get("items",[]) if i.get("img")}
    data=json.load(open(src)); items=[]
    for d in data["items"]:
        it={k:d.get(k) for k in K if k in d}; it["id"]=d["id"]
        if not str(it.get("img") or "").startswith("data:image/"):
            it.pop("img",None)
            if oldimg.get(d["id"]): it["img"]=oldimg[d["id"]]
        items.append(it)
    claims=[clean_claim(c) for c in data.get("claims",[])]
    meta={k:v for k,v in (data.get("meta") or {}).items() if k in ("title","due","note") and v} or prev.get("meta",{})
else:
    dbdir,pw=sys.argv[1:3]; items=[]
    for f in glob.glob(os.path.join(dbdir,"items","*.json")):
        d=json.load(open(f)); it={k:d.get(k) for k in K if k in d}; it["id"]=os.path.basename(f)[:-5]
        if not str(it.get("img") or "").startswith("data:image/"): it.pop("img",None)
        items.append(it)
    claims=[clean_claim(json.load(open(f)),os.path.basename(f)[:-5]) for f in glob.glob(os.path.join(dbdir,"claims","*.json"))]
    meta={}
    mp=os.path.join(dbdir,"meta","settings.json")
    if os.path.exists(mp):
        mm=json.load(open(mp)); meta={k:mm.get(k) for k in ("title","due","note") if mm.get(k)}
assert items, "no items"
snap={"items":items,"claims":claims,"meta":meta,"updated":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
salt=secrets.token_bytes(16);iv=secrets.token_bytes(12);n=200000
ct=AESGCM(kdf(pw,salt,n)).encrypt(iv,json.dumps(snap,separators=(",",":")).encode(),None)
e=lambda x:base64.b64encode(x).decode()
enc=json.dumps({"s":e(salt),"iv":e(iv),"n":n,"d":e(ct)})
h=h[:m.start(1)]+enc+h[m.end(1):]
open(page,"w").write(h); print(len(items),"items",len(claims),"claims",sum(1 for i in items if i.get("img")),"with photos",len(h)//1024,"KB")
