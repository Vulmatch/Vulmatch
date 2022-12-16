import os
import pickle
from common_library import p_c_sig,sub_p_c_sig,normalize_address
from pdb import set_trace as bp

#Transform the signature containing dictionary to a list to facilitate later signature finding. sig_type can be two values, "change" denotes the change sig. "add" denotes the addition.
class transformed_sig:
    def __init__(self, sig_type, sig,insn_number):
        self.sig_type = sig_type
        self.sig = sig
        self.insn_number=insn_number

class transformed_single_func_sigs:
    def __init__(self, transformed_vul_sigs,transformed_patch_sigs,total_vul_insn_number,total_patch_insn_number):
        self.transformed_vul_sigs = transformed_vul_sigs
        self.transformed_patch_sigs = transformed_patch_sigs
        self.total_vul_insn_number=total_vul_insn_number
        self.total_patch_insn_number=total_patch_insn_number



#Given a bin pickle path, read all the functions bin sig and transform the sig to delete insn address for later finding sig.
def read_bin_sig(bin_sig_pickle_file):
 transformed_sigs_dict={}
 f=open(bin_sig_pickle_file,'rb')
 sig_list=pickle.load(f)
 #print("length of sig_list:",len(sig_list))
 sig_number=0
 for sig in sig_list:
  sig_number+=1
  #print("")
  #print(sig.function_name,sig_number) 
  #print("vul signature:")
  if sig.function_name not in transformed_sigs_dict:
    transformed_sigs_dict[sig.function_name]=transformed_single_func_sigs([],[],0,0)
  #Transform vul sigs
  if sig.vul_signature[0]=="many_changed":#If is changed site
     transformed_vul_sig,current_vul_sig_insn_number=changed_many2list(sig.vul_signature[1])
     transformed_sigs_dict[sig.function_name].transformed_vul_sigs.append(transformed_vul_sig)
     transformed_sigs_dict[sig.function_name].total_vul_insn_number+=current_vul_sig_insn_number
  elif sig.vul_signature[0]=="one_changed":#If is changed site]
     #if sig.function_name=="EC_GROUP_get0_generator":
     # bp()
     transformed_vul_sig,current_vul_sig_insn_number=changed_one2list(sig.vul_signature[1])
     transformed_sigs_dict[sig.function_name].transformed_vul_sigs.append(transformed_vul_sig)
     transformed_sigs_dict[sig.function_name].total_vul_insn_number+=current_vul_sig_insn_number
  elif sig.vul_signature[0]=="added":#If is added site
   transformed_vul_sig,current_vul_sig_insn_number=added_sig2list(sig.vul_signature[1])
   transformed_sigs_dict[sig.function_name].transformed_vul_sigs.append(transformed_vul_sig)
   transformed_sigs_dict[sig.function_name].total_vul_insn_number+=current_vul_sig_insn_number
  elif sig.vul_signature[0]=="deleted":#If is deleted site
   transformed_vul_sig,current_vul_sig_insn_number=changed_sig2list(sig.vul_signature[1],"delete")
   transformed_sigs_dict[sig.function_name].transformed_vul_sigs.append(transformed_vul_sig)
   transformed_sigs_dict[sig.function_name].total_vul_insn_number+=current_vul_sig_insn_number
  #Transform patch sigs
  transformed_patch_sig,current_patch_sig_insn_number=changed_sig2list(sig.patch_signature,"patch")
  transformed_sigs_dict[sig.function_name].transformed_patch_sigs.append(transformed_patch_sig)
  transformed_sigs_dict[sig.function_name].total_patch_insn_number+=current_patch_sig_insn_number
 return transformed_sigs_dict

#Transform the dictionary-like sig into list-like sig. Returns yhe transformed sig and the sig's bin insn count. Change type can be "delete" or "patch".
def changed_sig2list(sig,change_type):
 result_sig=[]
 insn_number=0
 for block_addr in sig:
  block_insns=[]
  for insn_addr in sig[block_addr]:
    #block_insns.append(normalize_address(sig[block_addr][insn_addr]))
    block_insns.append(sig[block_addr][insn_addr])
    insn_number+=len(sig[block_addr][insn_addr])
  block_insns=block_insns
  result_sig.append(block_insns)
 result_sig_struct=transformed_sig(change_type,result_sig,insn_number)
 return result_sig_struct,insn_number

#Transform the dictionary-like sig into list-like sig. Returns yhe transformed sig and the sig's bin insn count
def added_sig2list(sig):
 result_sig=[]
 context_insn_num=0
 #block_num_dict={}
 for item in sig:
  transformed_item=[]
  for p_c_struct in item:
    transformed_p_c_struct=p_c_sig(None,None)
    #bp()
    #Process parents
    if len(p_c_struct.p)==0:
     transformed_p_c_struct.p=[]
    elif type(p_c_struct.p)==dict:#If is a single parent
     key_list=list(p_c_struct.p)
     #if key_list[0] not in block_num_dict:#Record block size
     # block_num_dict[key_list[0]]=len(p_c_struct.p[key_list[0]])
     block_asm=filter_push_pop(p_c_struct.p[key_list[0]])
     context_insn_num+=len(block_asm)
     #block_asm=normalize_address(block_asm)
     transformed_p_c_struct.p=block_asm
    elif type(p_c_struct.p)==list:#If is many parents
     transformed_p_c_struct.p=[]
     for parent in p_c_struct.p:
      key_list=list(parent)
      #if key_list[0] not in block_num_dict:#Record block size
      # if key_list[0]==' ':
      #  bp()
      # block_num_dict[key_list[0]]=len(parent[key_list[0]])
      block_asm=filter_push_pop(parent[key_list[0]])
      context_insn_num+=len(block_asm)
      #block_asm=normalize_address(block_asm)
      transformed_p_c_struct.p.append(block_asm)

    #Process children
    if len(p_c_struct.c)==0:
     transformed_p_c_struct.c=[]
    elif type(p_c_struct.c)==dict:#If is a single child
     key_list=list(p_c_struct.c)
     #if key_list[0] not in block_num_dict:#Record block size
     # block_num_dict[key_list[0]]=len(p_c_struct.c[key_list[0]])
     block_asm=filter_push_pop(p_c_struct.c[key_list[0]])
     context_insn_num+=len(block_asm)
     #block_asm=normalize_address(block_asm)
     
     transformed_p_c_struct.c=block_asm
    elif type(p_c_struct.c)==list:#If is many children
     transformed_p_c_struct.c=[]
     for child in p_c_struct.c:
      key_list=list(child)
      #if key_list[0] not in block_num_dict:#Record block size
      # block_num_dict[key_list[0]]=len(child[key_list[0]])
      block_asm=filter_push_pop(child[key_list[0]])
      context_insn_num+=len(block_asm)
      #block_asm=normalize_address(block_asm) 
      transformed_p_c_struct.c.append(block_asm)
    transformed_item.append(transformed_p_c_struct)
  result_sig.append(transformed_item)
 #context_insn_num=0
 #for block in block_num_dict:
 #  context_insn_num+=block_num_dict[block]
 result_sig_struct=transformed_sig("add",result_sig,context_insn_num)
 return result_sig_struct,context_insn_num

#Translate [sub_p_c_sig,sub_p_c_sig,,...dict] to a list
def changed_many2list(sig_list):
 transformed_sig_list=[]
 context_insn_num=0
 for item in sig_list:
  if type(item)==sub_p_c_sig:
   transformed_p_c_struct=sub_p_c_sig([],[]) 
   key=list(item.p)[0]#Because in many change structure, we define each sub_p_c_sig structure to have one parent only
   consecuive_asm_list=dic2list(item.p[key])
   block_asm=filter_push_pop(consecuive_asm_list)
   context_insn_num+=len(block_asm)
   #block_asm=normalize_address(block_asm)
   #bp()
   transformed_p_c_struct.p.append(block_asm)
   
   key_list1=list(item.c)
   for key1 in key_list1:
    consecuive_asm_list=dic2list(item.c[key1])
    block_asm=filter_push_pop(consecuive_asm_list)
    context_insn_num+=len(block_asm)
    #block_asm=normalize_address(block_asm)
    #bp()
    transformed_p_c_struct.c.append(block_asm)
   transformed_sig_list.append(transformed_p_c_struct)
  elif type(item)==dict:
    block=[]
    key=list(item)[0]
    for conse_insn in item[key]:
      block_asm=filter_push_pop(item[key][conse_insn])
      context_insn_num+=len(block_asm)
      block.append(block_asm)
    transformed_sig_list.append(block)
 result_sig_struct=transformed_sig("many_change",transformed_sig_list,context_insn_num)
 return result_sig_struct, context_insn_num
   
#Transform {addr:['insn','insn']} into ['insn','insn']
def dic2list(insn_dict):
 key=list(insn_dict)[0]
 return insn_dict[key]

#Translate sub_p_c_sig into a list.
def changed_one2list(one_sig):
 transformed_p_c_struct=sub_p_c_sig([],[])
 context_insn_num=0
 if len(list(one_sig.p))>0:
  p_block=list(one_sig.p)[0]
  for each_conse in one_sig.p[p_block]:#Each consecutive insns
    consecuive_asm_list=one_sig.p[p_block][each_conse]
    block_asm=filter_push_pop(consecuive_asm_list)
    #block_asm=normalize_address(block_asm)
    #bp()
    transformed_p_c_struct.p.append(block_asm)
    context_insn_num+=len(block_asm)
 if len(list(one_sig.c))>0:
  c_block=list(one_sig.c)[0]
  for each_conse in one_sig.c[c_block]:#Each consecutive insns
    consecuive_asm_list=one_sig.c[c_block][each_conse]
    block_asm=filter_push_pop(consecuive_asm_list)
    #block_asm=normalize_address(block_asm)
    #bp()
    transformed_p_c_struct.c.append(block_asm)
    context_insn_num+=len(block_asm)
 result_sig_struct=transformed_sig("one_change",transformed_p_c_struct,context_insn_num)
 return result_sig_struct,context_insn_num
 

   

#Delete all push and pop insns
def filter_push_pop(block_asm):
 filtered_asm=[]
 for insn in block_asm:
  if "push " in insn:
   continue
  elif "pop " in insn:
   continue
  else:
   filtered_asm.append(insn)
 return filtered_asm

