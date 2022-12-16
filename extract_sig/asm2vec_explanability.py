import pandas as pd
from common_library import func_vul_patch_signature,p_c_sig,sub_p_c_sig
from transform_sig import filter_push_pop,dic2list
import os
from pdb import set_trace as bp
import pickle

class single_func_sigs:
    def __init__(self, addr_n_offset,total_vul_insn_number):
        self.addr_n_offset = addr_n_offset
        self.total_vul_insn_number=total_vul_insn_number
        

def main():
 cve_folder="/home/nuc/Desktop/curl_cve"
 html_root_folder="/media/nuc/647A-5091/curl-"
 cves=os.listdir(cve_folder)
 sim_list=[]
 for cve in cves:
  cve_path=cve_folder+"/"+cve
  files=os.listdir(cve_path)
  for each in files:
    if each.startswith("bin_") and each.endswith("_insn_sig.pickle"):
      #Read pickle sigs
      f=open(cve_path+"/"+each,'rb')
      sig_list=pickle.load(f)
      sigs_dict=extract_insn_addr(sig_list)
      
      filename=each.split("bin_")[1].split("_insn_sig.pickle")[0]
      tmp_sim_list=check_asm_explaination(sigs_dict,html_root_folder,cve,filename)
      for sim in tmp_sim_list:
        sim_list.append(sim)
 total_sim=0
 sim_num=0
 for sim in sim_list:
   total_sim+=sim
   sim_num+=1
 print("avg:",total_sim*1.0/sim_num)
      
       
      
def check_asm_explaination(sigs_dict,html_root_folder,cve,filename):
 html_cve_path=html_root_folder+"/"+cve
 if not os.path.isdir(html_cve_path):
  return []
 files=os.listdir(html_cve_path)
 sim_list=[]
 for func in sigs_dict:
   print(cve,func)
   for each in files:
    if os.path.isfile(html_cve_path+"/"+each) and each.startswith(func) and each.find(filename)!=-1:
     #Read the asm2vec explnation for that c file's specific func
     asm_expln_table=pd.read_html(html_cve_path+"/"+each)
     addr_col=asm_expln_table[0][0]
     insn_col=asm_expln_table[0][1]
     sim=find_func_explanable_insn_rate(addr_col,insn_col,sigs_dict[func].addr_n_offset,sigs_dict[func].total_vul_insn_number)
     print("asm2vec","explanability:",sim)
     sim_list.append(sim)
 return sim_list
     
     
#Check how many insns in func_sigs is explained by asm2vec to be "found equivalent insns"
def find_func_explanable_insn_rate(addr_col,insn_col,func_sigs,total_vul_insn_number):
 found_equal_insn_num=0
 for sig in func_sigs:
  if type(sig)==tuple:
   found_equal_insn_num+=find_equal_insn_num(sig,addr_col,insn_col)
  elif type(sig)==list:
   for tuple0 in sig:
     found_equal_insn_num+=find_equal_insn_num(tuple0,addr_col,insn_col)
 sim= found_equal_insn_num*1.0/total_vul_insn_number
 return sim

  
def find_equal_insn_num(tuple0,addr_col,insn_col):
 found_equal_insn_num=0
 start_index=-1
 for addr_index in range(0,len(addr_col)):
  if type(addr_col[addr_index])==float:#skip NaN
   continue
  elif addr_col[addr_index]=="0x"+tuple0[0]+"+" or addr_col[addr_index]=="0x"+tuple0[0]:
   start_index=addr_index
   break
 if start_index!=-1:#Found the addr
   for offset in range(0,tuple0[1]):
     #print("tuple[1]",tuple0[1])
     if start_index+offset not in insn_col:
      bp()
     if type(insn_col[start_index+offset])==float:
      continue
     elif insn_col[start_index+offset].startswith("+") or insn_col[start_index+offset].startswith("-"):
      continue
     else:
      found_equal_insn_num+=1
 return found_equal_insn_num

def extract_insn_addr(sig_list):
 sigs_dict={}
 for sig in sig_list: 
   if sig.function_name not in sigs_dict:
     sigs_dict[sig.function_name]=single_func_sigs([],0)
   if sig.vul_signature[0]=="many_changed":#If is changed site
     addr_n_offset,vul_sig_insn_number=changed_many_addrs(sig.vul_signature[1])
     sigs_dict[sig.function_name].total_vul_insn_number+=vul_sig_insn_number
     sigs_dict[sig.function_name].addr_n_offset=addr_n_offset
   elif sig.vul_signature[0]=="one_changed":#If is changed site]
     #if sig.function_name=="EC_GROUP_get0_generator":
     # bp()
     addr_n_offset,vul_sig_insn_number=changed_one_addrs(sig.vul_signature[1])
     sigs_dict[sig.function_name].total_vul_insn_number+=vul_sig_insn_number
     sigs_dict[sig.function_name].addr_n_offset=addr_n_offset
   elif sig.vul_signature[0]=="added":#If is added site
     addr_n_offset,vul_sig_insn_number=added_sig_addrs(sig.vul_signature[1])
     sigs_dict[sig.function_name].total_vul_insn_number+=vul_sig_insn_number
     sigs_dict[sig.function_name].addr_n_offset=addr_n_offset
   elif sig.vul_signature[0]=="deleted":#If is deleted site
     addr_n_offset,vul_sig_insn_number=changed_sig_addrs(sig.vul_signature[1],"delete")
     sigs_dict[sig.function_name].total_vul_insn_number+=vul_sig_insn_number
     sigs_dict[sig.function_name].addr_n_offset=addr_n_offset
 return sigs_dict

#Calculate {addr:['insn','insn']} as 2
def dicSize(insn_dict):
 key=list(insn_dict)[0]
 return len(insn_dict[key])

#Translate [sub_p_c_sig,sub_p_c_sig,,...dict] to a list of addrs and offsets. Specifically, 
def changed_many_addrs(sig_list):
 result_sig_list=[]#A list recording all sigs' starting address and the following insns number (aka., offset)
 context_insn_num=0
 for item in sig_list:
  one_sig=[]#Used to record one sub_p_c_sig or one dict
  if type(item)==sub_p_c_sig: 
   key=list(item.p)[0]#Because in many change structure, we define each sub_p_c_sig structure to have one parent only
   consecuive_asm_list=dic2list(item.p[key])
   block_asm=filter_push_pop(consecuive_asm_list)
   #consecutive_insn_num=dicSize(item.p[key])
   one_sig.append((key,len(block_asm)))
   context_insn_num+=len(block_asm)
   
   key_list1=list(item.c)
   for key1 in key_list1:
    #consecutive_insn_num=dicSize(item.c[key1])
    consecuive_asm_list=dic2list(item.c[key1])
    block_asm=filter_push_pop(consecuive_asm_list)
    one_sig.append((key1,len(block_asm)))
    context_insn_num+=len(block_asm)
   result_sig_list.append(one_sig)
  elif type(item)==dict:
    key=list(item)[0]
    for conse_insn in item[key]:
      conse_asm=filter_push_pop(item[key][conse_insn])
      context_insn_num+=len(conse_asm)
      one_sig.append((conse_insn,len(conse_asm)))
    result_sig_list.append(one_sig)
 return result_sig_list, context_insn_num

#Translate sub_p_c_sig into a list.
def changed_one_addrs(one_sig):
 sig_list=[]#A list recording all sigs' starting address and the following insns number (aka., offset)
 context_insn_num=0
 if len(list(one_sig.p))>0:
  p_block=list(one_sig.p)[0]
  for each_conse in one_sig.p[p_block]:#Each consecutive insns
    consecuive_asm_list=one_sig.p[p_block][each_conse]
    block_asm=filter_push_pop(consecuive_asm_list)
    #block_asm=normalize_address(block_asm)
    #bp()
    sig_list.append((each_conse,len(block_asm)))
    context_insn_num+=len(block_asm)
 if len(list(one_sig.c))>0:
  c_block=list(one_sig.c)[0]
  for each_conse in one_sig.c[c_block]:#Each consecutive insns
    consecuive_asm_list=one_sig.c[c_block][each_conse]
    block_asm=filter_push_pop(consecuive_asm_list)
    
    sig_list.append((each_conse,len(block_asm)))
    context_insn_num+=len(block_asm)
 
 return sig_list,context_insn_num

#Transform the dictionary-like sig into list-like sig. Returns yhe transformed sig and the sig's bin insn count
def added_sig_addrs(sig):
 sig_list=[]#A list recording all sigs' starting address and the following insns number (aka., offset)
 context_insn_num=0
 #block_num_dict={}
 for item in sig:
  for p_c_struct in item:
    one_sig=[]#Used to record one p_c_sig or one dict
    #Process parents
    if len(p_c_struct.p)==0:
     pass
    elif type(p_c_struct.p)==dict:#If is a single parent
     key_list=list(p_c_struct.p)
     #if key_list[0] not in block_num_dict:#Record block size
     # block_num_dict[key_list[0]]=len(p_c_struct.p[key_list[0]])
     block_asm=filter_push_pop(p_c_struct.p[key_list[0]])
     context_insn_num+=len(block_asm)
     #block_asm=normalize_address(block_asm)
     one_sig.append((key_list[0],len(block_asm)))
    elif type(p_c_struct.p)==list:#If is many parents
     for parent in p_c_struct.p:
      key_list=list(parent)
      #if key_list[0] not in block_num_dict:#Record block size
      # if key_list[0]==' ':
      #  bp()
      # block_num_dict[key_list[0]]=len(parent[key_list[0]])
      block_asm=filter_push_pop(parent[key_list[0]])
      context_insn_num+=len(block_asm)
      one_sig.append((key_list[0],len(block_asm)))
      

    #Process children
    if len(p_c_struct.c)==0:
     pass
    elif type(p_c_struct.c)==dict:#If is a single child
     key_list=list(p_c_struct.c)
     #if key_list[0] not in block_num_dict:#Record block size
     # block_num_dict[key_list[0]]=len(p_c_struct.c[key_list[0]])
     block_asm=filter_push_pop(p_c_struct.c[key_list[0]])
     context_insn_num+=len(block_asm)
     #block_asm=normalize_address(block_asm)
    elif type(p_c_struct.c)==list:#If is many children
     for child in p_c_struct.c:
      key_list=list(child)
      #if key_list[0] not in block_num_dict:#Record block size
      # block_num_dict[key_list[0]]=len(child[key_list[0]])
      block_asm=filter_push_pop(child[key_list[0]])
      context_insn_num+=len(block_asm)
      #block_asm=normalize_address(block_asm) 
      one_sig.append((key_list[0],len(block_asm)))
    sig_list.append(one_sig)
  
 #context_insn_num=0
 #for block in block_num_dict:
 #  context_insn_num+=block_num_dict[block]
 return sig_list,context_insn_num

#Transform the dictionary-like sig into list-like sig. Returns yhe transformed sig and the sig's bin insn count. Change type can be "delete" or "patch".
def changed_sig_addrs(sig,change_type):
 sig_list=[]
 insn_number=0
 for block_addr in sig:
  block_insns=[]
  for insn_addr in sig[block_addr]:
    #block_insns.append(normalize_address(sig[block_addr][insn_addr]))
    sig_list.append((insn_addr,len(sig[block_addr][insn_addr])))
    insn_number+=len(sig[block_addr][insn_addr])
 
 return sig_list,insn_number

main()
