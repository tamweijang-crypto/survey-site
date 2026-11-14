const express=require("express"),bcrypt=require("bcryptjs"),crypto=require("crypto"),fs=require("fs"),path=require("path");
const F=process.env.DATA_FILE||path.join(__dirname,"data.json"),PROD=process.env.NODE_ENV==="production";
const PRESET={"行政事务部":1,"首相":1,"人事部":1,"文书员":1,"调查人员":1};
let db;try{db=JSON.parse(fs.readFileSync(F,"utf8"))}catch(e){db={users:[],surveys:[],resp:[]}}
const save=()=>{fs.writeFileSync(F+".tmp",JSON.stringify(db));fs.renameSync(F+".tmp",F)};
if(!db.users.find(u=>u.id==="A001")){db.users.push({id:"A001",name:"行政事务部",hash:bcrypt.hashSync(process.env.ADMIN_PASSWORD||"00100",10),role:"行政事务部",perms:{create:1,view:1,manage:1}});save()}
const S=new Map(),fails=new Map(),app=express();
app.set("trust proxy",1);app.use(express.json({limit:"300kb"}));
app.use((q,r,n)=>{r.set({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"same-origin"});n()});
const sid=q=>((q.headers.cookie||"").split(/;\s*/).find(c=>c.startsWith("sid="))||"").slice(4);
app.use((q,r,n)=>{const id=S.get(sid(q));q.me=id&&db.users.find(u=>u.id===id);n()});
const auth=p=>(q,r,n)=>!q.me?r.sendStatus(401):(p&&!q.me.perms[p])?r.sendStatus(403):n();
const pub=u=>({id:u.id,name:u.name,role:u.role,perms:u.perms}),str=(v,n)=>String(v||"").trim().slice(0,n);

app.post("/api/login",(q,r)=>{
  const f=fails.get(q.ip)||{n:0,t:Date.now()};if(Date.now()-f.t>9e5){f.n=0;f.t=Date.now()}
  if(f.n>=10)return r.status(429).json({error:"尝试次数过多，请 15 分钟后再试"});
  const u=db.users.find(x=>x.id===str(q.body.id,40));
  if(!u||!bcrypt.compareSync(String(q.body.pwd||""),u.hash)){f.n++;fails.set(q.ip,f);return r.status(401).json({error:"账号或密码错误"})}
  const t=crypto.randomBytes(24).toString("hex");S.set(t,u.id);
  r.set("Set-Cookie",`sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${PROD?"; Secure":""}`);r.json(pub(u));
});
app.post("/api/logout",(q,r)=>{S.delete(sid(q));r.sendStatus(204)});
app.get("/api/data",auth(),(q,r)=>{const m=q.me;
  r.json({me:pub(m),users:m.perms.manage?db.users.map(pub):[],surveys:db.surveys,resp:m.perms.view?db.resp:db.resp.filter(x=>x.uid===m.id)})});

app.post("/api/surveys",auth("create"),(q,r)=>{
  const b=q.body,title=str(b.title,200);
  const qs=(Array.isArray(b.qs)?b.qs:[]).slice(0,100).map(x=>{const type=["single","multi","text"].includes(x.type)?x.type:"text";
    return{t:str(x.t,500),type,o:type==="text"?[]:(Array.isArray(x.o)?x.o:[]).map(o=>str(o,200)).filter(Boolean).slice(0,50)}});
  if(!title||!qs.length||qs.some(x=>!x.t||(x.type!=="text"&&x.o.length<2)))return r.status(400).json({error:"问卷内容不完整"});
  const wd=q.me.perms.manage&&b.mode==="weighted";let w=null;
  if(wd){w={};for(const k in PRESET){const n=parseFloat(b.w&&b.w[k]);w[k]=isNaN(n)||n<0?1:n}}
  db.surveys.push({id:"s"+Date.now(),title,qs,by:q.me.id,mode:wd?"weighted":"equal",w});save();r.sendStatus(201);
});
app.delete("/api/surveys/:id",auth(),(q,r)=>{
  const s=db.surveys.find(x=>x.id===q.params.id);
  if(!s)return r.sendStatus(404);if(!q.me.perms.manage&&s.by!==q.me.id)return r.sendStatus(403);
  db.surveys=db.surveys.filter(x=>x!==s);db.resp=db.resp.filter(x=>x.sid!==s.id);save();r.sendStatus(204);
});
app.post("/api/respond",auth(),(q,r)=>{
  const s=db.surveys.find(x=>x.id===q.body.sid),a=q.body.ans;
  if(!s||!Array.isArray(a)||a.length!==s.qs.length)return r.sendStatus(400);
  if(db.resp.some(x=>x.sid===s.id&&x.uid===q.me.id))return r.status(409).json({error:"你已填写过此问卷"});
  const ans=s.qs.map((x,i)=>x.type==="text"?str(a[i],2000):(Array.isArray(a[i])?a[i]:[]).filter(v=>x.o.includes(v)).slice(0,x.type==="single"?1:50));
  const w=s.mode==="weighted"&&s.w[q.me.role]!==undefined?s.w[q.me.role]:1;
  db.resp.push({sid:s.id,uid:q.me.id,name:q.me.name,role:q.me.role,w,time:new Date().toLocaleString("zh-CN",{timeZone:"Asia/Kuala_Lumpur"}),ans});save();r.sendStatus(201);
});

app.post("/api/users",auth("manage"),(q,r)=>{
  const b=q.body,id=str(b.id,40),name=str(b.name,60);
  if(!id||!name||!PRESET[b.role])return r.status(400).json({error:"资料不完整"});
  const perms={};for(const k of["create","view","manage"])perms[k]=b.perms&&b.perms[k]?1:0;
  let role=b.role;if(id==="A001"){perms.create=perms.view=perms.manage=1;role="行政事务部"}
  let u=db.users.find(x=>x.id===id);
  if(!u){if(!b.pwd)return r.status(400).json({error:"请设置密码"});u={id};db.users.push(u)}
  Object.assign(u,{name,role,perms});
  if(b.pwd){u.hash=bcrypt.hashSync(String(b.pwd),10);for(const[t,i]of S)if(i===id&&t!==sid(q))S.delete(t)}
  save();r.sendStatus(204);
});
app.delete("/api/users/:id",auth("manage"),(q,r)=>{
  if(q.params.id==="A001")return r.status(400).json({error:"A001 不能删除"});
  db.users=db.users.filter(x=>x.id!==q.params.id);for(const[t,i]of S)if(i===q.params.id)S.delete(t);save();r.sendStatus(204);
});
app.use(express.static(path.join(__dirname,"public")));
app.listen(process.env.PORT||3000,()=>console.log("running"));
