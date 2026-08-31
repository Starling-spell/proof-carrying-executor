# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import hashlib
import json

POLICY="proof-carrying-executor-v1-exact-packet"
MAX_BODY=24000

@allow_storage
@dataclass
class Epoch:
    owner: Address
    agent: Address
    agent_accepted: bool
    intent_url: str
    intent_fingerprint: str
    manifest_url: str
    manifest_fingerprint: str
    constraints_json: str
    forbidden_json: str
    budget_remaining: u256
    action_head: u64
    state: str

@allow_storage
@dataclass
class Attempt:
    epoch_id: str
    logical_action: u64
    attempt: u64
    replacement_of: str
    parent_head: u64
    proposer: Address
    action_url: str
    action_hash: str
    state: str
    packet_json: str
    packet_fingerprint: str
    consumed: bool
    authorization_id: str

@allow_storage
@dataclass
class Receipt:
    attempt_id: str
    action_hash: str
    adapter: str
    operation: str
    parameters_hash: str
    budget_consumed: u256
    resulting_head: u64

class ProofCarryingExecutor(gl.Contract):
    epochs: TreeMap[str,Epoch]
    epoch_exists: TreeMap[str,bool]
    attempts: TreeMap[str,Attempt]
    attempt_exists: TreeMap[str,bool]
    slot_reserved: TreeMap[str,bool]
    slot_closed: TreeMap[str,bool]
    latest_attempt: TreeMap[str,str]
    attempt_count: TreeMap[str,u64]
    receipts: TreeMap[str,Receipt]
    receipt_exists: TreeMap[str,bool]
    active_epoch: TreeMap[str,str]
    allowed_adapters: TreeMap[str,bool]

    def __init__(self)->None: pass

    @gl.public.write
    def set_adapter(self,epoch_id:str,adapter:Address,allowed:bool)->None:
        epoch=self._epoch(self._id(epoch_id))
        if gl.message.sender_address!=epoch.owner: raise gl.vm.UserError("EXPECTED: owner only")
        self.allowed_adapters[str(adapter).lower()]=allowed

    @gl.public.write
    def create_epoch(self,epoch_id:str,agent:Address,intent_url:str,manifest_url:str,constraints_json:str,forbidden_json:str,budget:u256)->None:
        eid=self._id(epoch_id);other=Address(str(agent))
        if self.epoch_exists.get(eid,False): raise gl.vm.UserError("EXPECTED: epoch exists")
        if other==gl.message.sender_address: raise gl.vm.UserError("EXPECTED: independent agent")
        if int(budget)<=0: raise gl.vm.UserError("EXPECTED: positive budget")
        iu=self._url(intent_url);mu=self._url(manifest_url);anchors=self._anchor_consensus(iu,mu)
        self.epochs[eid]=Epoch(gl.message.sender_address,other,False,iu,anchors["intent_fingerprint"],mu,anchors["manifest_fingerprint"],self._strings(constraints_json,"constraints",1),self._strings(forbidden_json,"forbidden",0),budget,u64(0),"AWAITING_AGENT")
        self.epoch_exists[eid]=True

    @gl.public.write
    def accept_epoch(self,epoch_id:str)->None:
        eid=self._id(epoch_id);epoch=self._epoch(eid)
        if gl.message.sender_address!=epoch.agent: raise gl.vm.UserError("EXPECTED: assigned agent only")
        if epoch.agent_accepted: raise gl.vm.UserError("EXPECTED: epoch accepted")
        epoch.agent_accepted=True;epoch.state="ACTIVE";self.epochs[eid]=epoch;self.active_epoch[str(epoch.agent).lower()]=eid

    @gl.public.write
    def submit_action(self,attempt_id:str,epoch_id:str,logical_action:u64,action_url:str,action_hash:str)->None:
        aid=self._id(attempt_id);eid=self._id(epoch_id);epoch=self._epoch(eid)
        if gl.message.sender_address!=epoch.agent or not epoch.agent_accepted: raise gl.vm.UserError("EXPECTED: accepted agent only")
        if self.active_epoch.get(str(epoch.agent).lower(),"")!=eid: raise gl.vm.UserError("EXPECTED: inactive policy epoch")
        if self.attempt_exists.get(aid,False): raise gl.vm.UserError("EXPECTED: attempt exists")
        expected=u64(int(epoch.action_head)+1)
        if int(logical_action)!=int(expected): raise gl.vm.UserError("EXPECTED: next logical action")
        slot=eid+":"+str(int(expected))
        if self.slot_closed.get(slot,False): raise gl.vm.UserError("EXPECTED: action slot closed")
        replacement="";number=u64(1)
        if self.slot_reserved.get(slot,False):
            replacement=self.latest_attempt.get(slot,"");prior=self._attempt(replacement)
            if prior.state not in ("UNAVAILABLE","REQUIRES_REVISION","DENIED","EXPIRED"): raise gl.vm.UserError("EXPECTED: prior attempt not retryable")
            number=u64(int(self.attempt_count.get(slot,u64(0)))+1)
        self.attempts[aid]=Attempt(eid,expected,number,replacement,epoch.action_head,gl.message.sender_address,self._url(action_url),self._hash(action_hash),"SUBMITTED","","",False,"")
        self.attempt_exists[aid]=True;self.slot_reserved[slot]=True;self.latest_attempt[slot]=aid;self.attempt_count[slot]=number

    @gl.public.write
    def evaluate_action(self,attempt_id:str)->None:
        aid=self._id(attempt_id);item=self._attempt(aid);epoch=self._epoch(item.epoch_id)
        if gl.message.sender_address not in (epoch.owner,epoch.agent): raise gl.vm.UserError("EXPECTED: epoch party only")
        if item.state!="SUBMITTED": raise gl.vm.UserError("EXPECTED: attempt not submitted")
        if self.active_epoch.get(str(epoch.agent).lower(),"")!=item.epoch_id: item.state="STALE";self.attempts[aid]=item;return
        slot=item.epoch_id+":"+str(int(item.logical_action))
        if self.latest_attempt.get(slot,"")!=aid or int(item.logical_action)!=int(epoch.action_head)+1 or int(item.parent_head)!=int(epoch.action_head):
            item.state="STALE";self.attempts[aid]=item;return
        packet=self._decision_consensus(aid,item,epoch);canonical=json.dumps(packet,sort_keys=True,separators=(",",":"))
        item.packet_json=canonical;item.packet_fingerprint=hashlib.sha256(canonical.encode()).hexdigest();item.state=packet["decision"];self.attempts[aid]=item

    @gl.public.write
    def consume_authorization(self,attempt_id:str)->None:
        aid=self._id(attempt_id);item=self._attempt(aid);epoch=self._epoch(item.epoch_id)
        if gl.message.sender_address!=epoch.owner: raise gl.vm.UserError("EXPECTED: owner only")
        if self.active_epoch.get(str(epoch.agent).lower(),"")!=item.epoch_id: raise gl.vm.UserError("EXPECTED: inactive policy epoch")
        if item.state!="AUTHORIZED" or item.consumed: raise gl.vm.UserError("EXPECTED: authorization unavailable")
        slot=item.epoch_id+":"+str(int(item.logical_action))
        if self.latest_attempt.get(slot,"")!=aid or self.slot_closed.get(slot,False) or int(item.logical_action)!=int(epoch.action_head)+1: raise gl.vm.UserError("EXPECTED: stale authorization")
        packet=json.loads(item.packet_json);cost=u256(int(packet["budget_required"]))
        if int(cost)>int(epoch.budget_remaining): raise gl.vm.UserError("EXPECTED: budget changed")
        authorization_id=hashlib.sha256((item.epoch_id+":"+str(int(item.logical_action))+":"+str(int(item.attempt))+":"+item.action_hash).encode()).hexdigest()
        if not self.allowed_adapters.get(str(packet["target_adapter"]).lower(),False): raise gl.vm.UserError("EXPECTED: adapter not allowed")
        item.consumed=True;item.state="DISPATCHED";item.authorization_id=authorization_id;self.attempts[aid]=item;self.slot_closed[slot]=True
        epoch.budget_remaining=u256(int(epoch.budget_remaining)-int(cost));epoch.action_head=item.logical_action;self.epochs[item.epoch_id]=epoch
        self.receipts[aid]=Receipt(aid,item.action_hash,packet["target_adapter"],packet["operation"],packet["parameters_hash"],cost,item.logical_action);self.receipt_exists[aid]=True
        adapter=gl.get_contract_at(Address(packet["target_adapter"]));adapter.emit(on="executed").execute(authorization_id,item.action_hash,packet["operation"],packet["parameters_hash"])

    @gl.public.view
    def get_epoch(self,epoch_id:str)->Epoch: return self._epoch(self._id(epoch_id))
    @gl.public.view
    def get_attempt(self,attempt_id:str)->Attempt: return self._attempt(self._id(attempt_id))
    @gl.public.view
    def get_receipt(self,attempt_id:str)->Receipt:
        aid=self._id(attempt_id)
        if not self.receipt_exists.get(aid,False): raise gl.vm.UserError("EXPECTED: unknown receipt")
        return self.receipts[aid]
    @gl.public.view
    def is_authorized(self,attempt_id:str,packet_fingerprint:str)->bool:
        aid=self._id(attempt_id);item=self._attempt(aid);epoch=self._epoch(item.epoch_id);slot=item.epoch_id+":"+str(int(item.logical_action))
        return item.state=="AUTHORIZED" and not item.consumed and item.packet_fingerprint==packet_fingerprint.strip().lower() and self.active_epoch.get(str(epoch.agent).lower(),"")==item.epoch_id and self.latest_attempt.get(slot,"")==aid and not self.slot_closed.get(slot,False) and int(item.parent_head)==int(epoch.action_head) and int(item.logical_action)==int(epoch.action_head)+1

    def _anchor_consensus(self,intent_url,manifest_url):
        def recompute():
            intent=self._fetch(intent_url);manifest=self._fetch(manifest_url)
            return {"policy":POLICY,"intent_url":intent_url,"manifest_url":manifest_url,"source_statuses":[intent["status"],manifest["status"]],"http_statuses":[intent["http"],manifest["http"]],"intent_fingerprint":intent["fingerprint"],"manifest_fingerprint":manifest["fingerprint"]}
        def validate(res):
            if not isinstance(res,gl.vm.Return): return False
            leader=res.calldata;validator=recompute();return self._valid_anchor(leader,intent_url,manifest_url) and self._valid_anchor(validator,intent_url,manifest_url) and leader==validator
        result=gl.vm.run_nondet_unsafe(recompute,validate)
        if not self._valid_anchor(result,intent_url,manifest_url) or result["source_statuses"]!=["OK","OK"]: raise gl.vm.UserError("EXTERNAL: baseline unavailable")
        return result

    def _decision_consensus(self,aid,item,epoch):
        def recompute():
            intent=self._fetch(epoch.intent_url);manifest=self._fetch(epoch.manifest_url);action=self._fetch(item.action_url)
            im=intent["status"]=="OK" and intent["fingerprint"]==epoch.intent_fingerprint;mm=manifest["status"]=="OK" and manifest["fingerprint"]==epoch.manifest_fingerprint;parsed=self._action(action["body"]) if action["status"]=="OK" and action["fingerprint"]==item.action_hash else self._empty_action()
            semantic={"goal":"UNKNOWN","constraints":"UNKNOWN","forbidden":"UNKNOWN","rollback":"UNKNOWN"}
            if im and mm and parsed["valid"]:
                raw=gl.nondet.exec_prompt("Evaluate this action against the anchored intent and manifest. Return JSON only: goal ALIGNED|MISALIGNED|UNKNOWN; constraints PRESERVED|VIOLATED|UNKNOWN; forbidden CLEAR|VIOLATED|UNKNOWN; rollback PRESENT|MISSING|NOT_REQUIRED|UNKNOWN. Intent: "+intent["body"]+"\nManifest: "+manifest["body"]+"\nRegistered constraints: "+epoch.constraints_json+"\nForbidden: "+epoch.forbidden_json+"\nAction: "+action["body"],response_format="json")
                semantic={"goal":self._enum(raw,"goal",("ALIGNED","MISALIGNED","UNKNOWN")),"constraints":self._enum(raw,"constraints",("PRESERVED","VIOLATED","UNKNOWN")),"forbidden":self._enum(raw,"forbidden",("CLEAR","VIOLATED","UNKNOWN")),"rollback":self._enum(raw,"rollback",("PRESENT","MISSING","NOT_REQUIRED","UNKNOWN"))}
            unavailable=any(x["status"]!="OK" for x in (intent,manifest,action));baseline=im and mm;budget_ok=parsed["budget"]<=int(epoch.budget_remaining)
            authorized=baseline and parsed["valid"] and action["fingerprint"]==item.action_hash and semantic["goal"]=="ALIGNED" and semantic["constraints"]=="PRESERVED" and semantic["forbidden"]=="CLEAR" and semantic["rollback"] in ("PRESENT","NOT_REQUIRED") and budget_ok
            decision="UNAVAILABLE" if unavailable else ("BASELINE_DRIFT" if not im else ("IDENTITY_BREAK" if not mm else ("AUTHORIZED" if authorized else ("DENIED" if semantic["forbidden"]=="VIOLATED" or not budget_ok else "REQUIRES_REVISION"))))
            packet={"policy":POLICY,"epoch_id":item.epoch_id,"logical_action":int(item.logical_action),"attempt":int(item.attempt),"replacement_of":item.replacement_of,"intent_source_status":intent["status"],"manifest_source_status":manifest["status"],"action_source_status":action["status"],"fetched_intent_fingerprint":intent["fingerprint"],"stored_intent_fingerprint":epoch.intent_fingerprint,"intent_baseline_match":im,"fetched_manifest_fingerprint":manifest["fingerprint"],"stored_manifest_fingerprint":epoch.manifest_fingerprint,"identity_baseline_match":mm,"action_hash":item.action_hash,"fetched_action_hash":action["fingerprint"],"target_adapter":parsed["adapter"],"operation":parsed["operation"],"parameters_hash":parsed["parameters_hash"],"goal_alignment":semantic["goal"],"constraints_preserved":semantic["constraints"],"forbidden_actions":semantic["forbidden"],"budget_required":parsed["budget"],"budget_remaining":int(epoch.budget_remaining),"budget_ok":budget_ok,"rollback":semantic["rollback"],"decision":decision}
            packet["packet_fingerprint"]=hashlib.sha256(json.dumps(packet,sort_keys=True,separators=(",",":")).encode()).hexdigest();return packet
        def validate(res):
            if not isinstance(res,gl.vm.Return): return False
            leader=res.calldata;validator=recompute();return self._valid_packet(leader,item,epoch) and self._valid_packet(validator,item,epoch) and leader==validator
        result=gl.vm.run_nondet_unsafe(recompute,validate)
        if not self._valid_packet(result,item,epoch): raise gl.vm.UserError("LLM_ERROR: invalid decision packet")
        return result

    def _valid_anchor(self,r,iu,mu): return isinstance(r,dict) and r.get("policy")==POLICY and r.get("intent_url")==iu and r.get("manifest_url")==mu and isinstance(r.get("source_statuses"),list) and len(r["source_statuses"])==2 and len(str(r.get("intent_fingerprint","")))==64 and len(str(r.get("manifest_fingerprint","")))==64
    def _valid_packet(self,r,item,epoch): return isinstance(r,dict) and r.get("policy")==POLICY and r.get("epoch_id")==item.epoch_id and int(r.get("logical_action",0))==int(item.logical_action) and int(r.get("attempt",0))==int(item.attempt) and r.get("replacement_of")==item.replacement_of and r.get("stored_intent_fingerprint")==epoch.intent_fingerprint and r.get("stored_manifest_fingerprint")==epoch.manifest_fingerprint and r.get("decision") in ("AUTHORIZED","UNAVAILABLE","BASELINE_DRIFT","IDENTITY_BREAK","DENIED","REQUIRES_REVISION") and len(str(r.get("packet_fingerprint","")))==64
    def _action(self,body):
        try:
            raw=json.loads(body);adapter=self._id(str(raw.get("adapter","")));operation=self._id(str(raw.get("operation","")));params=raw.get("parameters");budget=int(raw.get("budget_required",-1));rollback=bool(raw.get("rollback_present",False))
            if not isinstance(params,dict) or budget<0: return self._empty_action()
            ph=hashlib.sha256(json.dumps(params,sort_keys=True,separators=(",",":")).encode()).hexdigest();return {"valid":True,"adapter":adapter,"operation":operation,"parameters_hash":ph,"budget":budget,"rollback":rollback}
        except Exception: return self._empty_action()
    def _empty_action(self): return {"valid":False,"adapter":"","operation":"","parameters_hash":hashlib.sha256(b"").hexdigest(),"budget":0,"rollback":False}
    def _fetch(self,url):
        try:
            r=gl.nondet.web.get(url);status=int(getattr(r,"status_code",getattr(r,"status",0)));body=r.body.decode("utf-8",errors="ignore")[:MAX_BODY];compact=" ".join(body.strip().split());ok=200<=status<300 and len(compact)>0
            return {"status":"OK" if ok else "UNAVAILABLE","http":status,"fingerprint":hashlib.sha256(compact.encode()).hexdigest(),"body":body if ok else ""}
        except Exception:return {"status":"UNAVAILABLE","http":0,"fingerprint":hashlib.sha256(b"").hexdigest(),"body":""}
    def _strings(self,text,label,minimum):
        try:raw=json.loads(text)
        except Exception:raise gl.vm.UserError("EXPECTED: invalid "+label)
        if not isinstance(raw,list) or len(raw)<minimum or len(raw)>12:raise gl.vm.UserError("EXPECTED: invalid "+label)
        return json.dumps([self._text(str(x),label) for x in raw],sort_keys=True,separators=(",",":"))
    def _enum(self,raw,key,allowed):
        value=str(raw.get(key,"UNKNOWN") if isinstance(raw,dict) else "UNKNOWN").strip().upper();return value if value in allowed else "UNKNOWN"
    def _epoch(self,eid):
        if not self.epoch_exists.get(eid,False):raise gl.vm.UserError("EXPECTED: unknown epoch")
        return self.epochs[eid]
    def _attempt(self,aid):
        if not self.attempt_exists.get(aid,False):raise gl.vm.UserError("EXPECTED: unknown attempt")
        return self.attempts[aid]
    def _id(self,value):
        out=value.strip()
        if len(out)<1 or len(out)>80 or ":" in out:raise gl.vm.UserError("EXPECTED: invalid id")
        return out
    def _text(self,value,label):
        out=" ".join(value.strip().split())
        if len(out)<1 or len(out)>1800:raise gl.vm.UserError("EXPECTED: invalid "+label)
        return out
    def _hash(self,value):
        out=value.strip().lower()
        if len(out)!=64 or any(c not in "0123456789abcdef" for c in out):raise gl.vm.UserError("EXPECTED: invalid hash")
        return out
    def _url(self,value):
        out=value.strip()
        if len(out)>512 or not out.startswith("https://") or "localhost" in out.lower() or "127.0.0.1" in out:raise gl.vm.UserError("EXPECTED: invalid public URL")
        return out
