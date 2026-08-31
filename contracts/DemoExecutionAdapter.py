# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass

@allow_storage
@dataclass
class AdapterReceipt:
    authorization_id: str
    action_hash: str
    operation: str
    parameters_hash: str

class DemoExecutionAdapter(gl.Contract):
    executor: Address
    used: TreeMap[str,bool]
    receipts: TreeMap[str,AdapterReceipt]

    def __init__(self,executor:Address)->None:
        self.executor=Address(str(executor))

    @gl.public.write
    def execute(self,authorization_id:str,action_hash:str,operation:str,parameters_hash:str)->None:
        if gl.message.sender_address!=self.executor: raise gl.vm.UserError("EXPECTED: executor only")
        if self.used.get(authorization_id,False): raise gl.vm.UserError("EXPECTED: authorization consumed")
        self.used[authorization_id]=True
        self.receipts[authorization_id]=AdapterReceipt(authorization_id,action_hash,operation,parameters_hash)

    @gl.public.view
    def get_receipt(self,authorization_id:str)->AdapterReceipt:
        if not self.used.get(authorization_id,False): raise gl.vm.UserError("EXPECTED: unknown authorization")
        return self.receipts[authorization_id]

