import pickle
from pdb import set_trace as bp
import os
from common_library import func_vul_patch_signature,increase_order,write_pickle,construct_diff_insn_list,comma2list,sub_p_c_sig
import angr
from extract_insn_from_bin_lib import *
from transform_sig import normalize_address

class symbol_record:#Each such record records one source code line and its corresponding binary instructions. The source code lines can be many because objdump shows a context sometimes. But the last line in the showed source instructions always points to the source code line number.
    def __init__(self, src_lines,bin_lines):
        self.src_lines = src_lines
        self.bin_lines=bin_lines

#Given a source code signature, find its corresponding instructions in binary code, for both vulnerable version and patched version. We have two types of signatures, insn signature and struct signature. This function specifically treats the insn signature. This is because, teach insn signature should be consecutive src lines. Thus it is reasonable to accumulate the lines' corresponding bin lines together. But structure signature can be huge and non-consecutive. Thus we need to find their version0's line A maps to version1's which line first.
def find_insn_sig_from_bin(src_sig,changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,bin_addr_insn0,bin_addr_insn1,blocks_context0,blocks_context1,block_addrs0,block_addrs1,src_line_map):
 vul_bin_insns=[]
 patch_bin_insns=[]
 vul_bin_insns={}
 patch_bin_insns={}
 not_found_vul_line=[]
 not_found_patch_line=[]
 #if src_sig.function_name=="EC_GROUP_get0_generator":
 # bp()
 if src_sig.vul_signature:
   vul_bin_insns,not_found_vul_line=process_vul_bin_sig(src_sig,source_bin_map0,bin_addr_insn0,block_addrs0)
   if src_sig.patch_signature:#The patch is a change
     patch_bin_insns,not_found_patch_line=process_patch_bin_sig(src_sig,source_bin_map1,bin_addr_insn1,block_addrs1)
     if len(vul_bin_insns)==0 and len(patch_bin_insns)==0:#Not found the bin insns for both vul signatuer and patch signature
      return None,not_found_vul_line,not_found_patch_line
     elif len(vul_bin_insns)>0:
      f_vul_bin_insns,f_patch_bin_insns=filter_same_bin_insn(vul_bin_insns,patch_bin_insns,blocks_context0[src_sig.function_name],bin_addr_insn0[src_sig.function_name],block_addrs0[src_sig.function_name])
      
     elif len(vul_bin_insns)==0:
      return None,not_found_vul_line,not_found_patch_line
   else:#The patch is a delete
     if len(vul_bin_insns)>0:
      f_vul_bin_insns=("deleted",vul_bin_insns)
      f_patch_bin_insns=[]
     else:
      f_vul_bin_insns=None
 elif src_sig.patch_signature:#The patch is an addition, thus no vul sig, only patch sig.
   #if src_sig.function_name=="_TIFFVSetField":
   # bp()
   f_vul_bin_insns=process_add_bin_sig(src_sig,changed_src_lines1,added_src_lines1,source_bin_map0,\
source_bin_map1,bin_addr_insn0,bin_addr_insn1,blocks_context0,blocks_context1,\
block_addrs0,block_addrs1,src_line_map)
   f_patch_bin_insns,not_found_patch_line=process_patch_bin_sig(src_sig,source_bin_map1,bin_addr_insn1,block_addrs1)
 
 if f_vul_bin_insns==None:
   return None,not_found_vul_line,not_found_patch_line
 elif len(f_vul_bin_insns)==0:
   return None,not_found_vul_line,not_found_patch_line
 else:
  bin_sig=func_vul_patch_signature(src_sig.function_name,f_vul_bin_insns,f_patch_bin_insns)
  return bin_sig,not_found_vul_line,not_found_patch_line
  


def process_add_bin_sig(src_sig,changed_src_lines1,added_src_lines1,source_bin_map0,\
source_bin_map1,bin_addr_insn0,bin_addr_insn1,blocks_context0,blocks_context1,\
block_addrs0,block_addrs1,src_line_map):
 vul_bin_insns=[]
 name=src_sig.function_name
 #if n=='verifystatus':
 #  bp()
 bin_insns0=find_add_vul_sig(src_sig.patch_signature,changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,bin_addr_insn0[name],bin_addr_insn1[name],blocks_context0[name],blocks_context1[name],block_addrs0[name],block_addrs1[name],src_line_map)
 for bin_insn in bin_insns0:
    vul_bin_insns.append(bin_insn)
 if bin_insns0==[]:
    return None
 return ("added",vul_bin_insns)

def process_vul_bin_sig(src_sig,source_bin_map0,bin_addr_insn0,block_addrs0):
  vul_bin_insns=[]
  not_found_vul_line=[]
  print("find src_sig.vul_signature")
  for line_index in src_sig.vul_signature:
   #if line_index==256:
   # bp()
   #if src_sig.function_name=="setcharset" and line_index==199:
   # bp()
   bin_insns0=find_bin_insn_by_src_line_index(line_index,src_sig.vul_signature[line_index],source_bin_map0,bin_addr_insn0[src_sig.function_name])
   for bin_insn in bin_insns0:
    vul_bin_insns.append(bin_insn)
   
   if bin_insns0==[]:
    #if src_sig.function_name=="setcharset":
    #  bp()
    not_found_vul_line.append((src_sig.function_name,line_index,src_sig.vul_signature[line_index]))
  #bp()
  vul_bin_insns=group_by_block(vul_bin_insns,block_addrs0[src_sig.function_name])
  #if len(vul_bin_insns)==0:
  #  bp()
  return vul_bin_insns,not_found_vul_line

def process_patch_bin_sig(src_sig,source_bin_map1,bin_addr_insn1,block_addrs1):
  patch_bin_insns=[]
  not_found_patch_line=[]
  print("find src_sig.patch_signature")
  #if 696 in src_sig.patch_signature:
  #  bp()
  for line_index in src_sig.patch_signature:
   bin_insns1=find_bin_insn_by_src_line_index(line_index,src_sig.patch_signature[line_index],source_bin_map1,bin_addr_insn1[src_sig.function_name])
   for bin_insn in bin_insns1:
    patch_bin_insns.append(bin_insn)
   
   if bin_insns1==[]:
   # if src_sig.function_name=="setcharset":
   #   bp()
    not_found_patch_line.append((src_sig.function_name,line_index,src_sig.patch_signature[line_index]))
  #if len(patch_bin_insns)==0:
  #  bp()
  patch_bin_insns=group_by_block(patch_bin_insns,block_addrs1[src_sig.function_name])
  return patch_bin_insns,not_found_patch_line

#Even thought the src diff tells you it is a change, on binary level, it still can be a "add" patch. We need to filter out the common part of vul bin sigs and patch bin sigs, if there are any common part.
def filter_same_bin_insn(vul_bin_insns,patch_bin_insns,block_context0,bin_addr_insn0,block_addrs0):
 ''' vul_common_blocks=[]
 patch_common_blocks=[]
 #Delete common part
 for block in vul_bin_insns:
   patch_block=has_common_bin_sig(vul_bin_insns[block],patch_bin_insns)
   if patch_block:
     vul_common_blocks.append(block)
     if patch_block not in patch_common_blocks:
      patch_common_blocks.append(patch_block)
 bp()
 patch_unique_blocks={}
 for block in patch_bin_insns:
  if block not in patch_common_blocks:
   patch_unique_blocks[block]=patch_bin_insns[block]
 vul_unique_blocks={}
 for block in vul_bin_insns:
  if block not in vul_common_blocks:
   vul_unique_blocks[block]=vul_bin_insns[block]'''
 vul_unique_blocks,patch_unique_blocks=has_common_bin_sig(vul_bin_insns,patch_bin_insns)
 #bp()
 
 if len(vul_bin_insns)>1:#Has insns from more than one block
  vul_bin_insns_n_relations=get_vul_bin_insns_relation(vul_bin_insns,block_context0)
 elif len(vul_bin_insns)==1:#Insns all from one block
  vul_bin_insns_n_relations=get_vul_bin_insn_context(vul_bin_insns,block_context0,bin_addr_insn0,block_addrs0)
 '''else:#Has no vul unique block
  if len(vul_bin_insns)>1:
   vul_bin_insns_n_relations=get_vul_bin_insns_relation(vul_bin_insns,block_context0)
  else:vul_bin_insns_n_relations=get_vul_bin_insn_context(vul_bin_insns,block_context0,bin_addr_insn0,block_addrs0)'''
 result=[]
 for each in vul_bin_insns_n_relations:
    result.append(each)
 result.append(vul_unique_blocks) 
 return result,patch_unique_blocks
  
#Return the unique vul and patch insns. vul_bin_insns is the vul blocks' insns, in the form of:{block:{addr:[],addr:[]},block:{addr:[]}}. patch_bin_insns is in the form of {block:{addr:[],addr:[]},block:{addr:[]}}.
def has_common_bin_sig(vul_bin_insns,patch_bin_insns):
 common_vul={}#Record common insns addrs and its insns in vul 
 common_patch={}#Record common insns addrs and its insns in patch
 for block in vul_bin_insns:
  vul_block_insns=vul_bin_insns[block]
  for insn_addr in vul_block_insns:#For each consecutive insns in vul
   vul_conse_insns=normalize_address(vul_block_insns[insn_addr])
   for block in patch_bin_insns:#For each block in patch
    patch_block_insns=patch_bin_insns[block]
    for each_insn in patch_block_insns:#For each consecutive insns
      #if each_insn in common_patch:#If this patch consecutive insn already has something in common with vul, just skip it.
      #  continue
      patch_conse_insns=normalize_address(patch_block_insns[each_insn])
      common_insns=has_common_insns(vul_conse_insns,patch_conse_insns)
      if len(common_insns)>0:
       if insn_addr not in common_vul:
        common_vul[insn_addr]=[]
       for insn in common_insns:
         common_vul[insn_addr].append(insn)
       if each_insn not in common_patch:
        common_patch[each_insn]=[]
       for insn in common_insns:
         common_patch[each_insn].append(insn)
 filtered_vul_bin_insns=filter_common_bin(vul_bin_insns,common_vul)
 filtered_patch_bin_insns=filter_common_bin(patch_bin_insns,common_patch)
 #bp()
 return filtered_vul_bin_insns,filtered_patch_bin_insns
 
#Delete the common insns in the bin_insns
def filter_common_bin(bin_insns,common_vul): 
 result_bin_insns={}
 for block in bin_insns:
  new_insns={}
  for insn_addr in bin_insns[block]:
   normalized_insn_bin=normalize_address(bin_insns[block][insn_addr])
   if insn_addr in common_vul:#If we have recorded that this consecutive insn has common insn
    for insn in normalized_insn_bin:
     if insn in common_vul[insn_addr]:#Skip the common insns
       continue
     else:#This insn is unique
       if insn_addr not in new_insns:
        new_insns[insn_addr]=[insn]
       else:
        new_insns[insn_addr].append(insn)
   else:
    new_insns[insn_addr]=normalized_insn_bin
  if len(new_insns)>0:
   result_bin_insns[block]=new_insns
 return result_bin_insns      

#vul_conse_insns and patch_conse_insns are all a list of insns. 
def has_common_insns(vul_conse_insns,patch_conse_insns):
 common_insns=[]
 for insn0 in vul_conse_insns:
   if insn0 in patch_conse_insns:
     common_insns.append(insn0)
 return common_insns

#Make the changed vul bin insns in a control-flow relation. We devide the sig into parent-children lists. This type of bin insn is a list consists of dict (for insns not have any parent- child - relations to other insns in the vul sig) and sub_p_c_sig (for all the insns have parent- or child- relations to each other).
def get_vul_bin_insns_relation(vul_bin_insns,block_context0):
 result_sig_list=[]
 considered_blocks=[]#Record the children already put into the context sig.
 for block in vul_bin_insns:
  has_sub_p_c_structure=False#Is true if we find there is such a sub_p_c structure.
  parent_block={}
  parent_block[block]=vul_bin_insns[block]
  #bp()
  children=block_context0[block].successors
  children_blocks={}
  for child in children:
   if child in vul_bin_insns:
    has_sub_p_c_structure=True
    children_blocks[child]=vul_bin_insns[child]
    if child not in considered_blocks:
     considered_blocks.append(child)
  if has_sub_p_c_structure==True:
   if block not in considered_blocks:
    considered_blocks.append(block)
  if len(children_blocks)>0:#If has a parent-child structure
   result_sig_list.append(sub_p_c_sig(parent_block,children_blocks))
  elif block not in considered_blocks:#A unique block insn
   result_sig_list.append({block:vul_bin_insns[block]})
 #bp()
 return ("many_changed",result_sig_list)

#vul_bin_insns only has one consecutive insn, we extract its parent, if any, as its context. If no parent, we extract its child as its context. This type of sig is a single sub_p_c_sig.
def get_vul_bin_insn_context(vul_bin_insns,block_context0,bin_addr_insn0,block_addrs0):
 block_addrs=list(vul_bin_insns)[0]
 #Look for parent
 parent_blocks={}
 parent_addrs=block_context0[block_addrs].predecessors
 for parent in parent_addrs:
  parent_block_dict=get_disasm_of_block(block_addrs0[parent],bin_addr_insn0)
  parent_blocks[parent]=parent_block_dict
 if len(parent_blocks)>0:
  children_blocks={block_addrs:vul_bin_insns[block_addrs]}
  return ("one_changed",sub_p_c_sig(parent_blocks,children_blocks))
 
 #Not found parent, find children
 elif len(parent_blocks)==0:
  children_blocks={}
  children_addrs=block_context0[block_addrs].successors
  for child in children_addrs:
   child_block_dict=get_disasm_of_block(block_addrs0[child],bin_addr_insn0)
   children_blocks[child]=child_block_dict
  parent_blocks={block_addrs:vul_bin_insns[block_addrs]}
  #bp()
  return ("one_changed",sub_p_c_sig(parent_blocks,children_blocks))
 

#For example, for xxx_insn_sig.pickle, we find all its signatures' corresponding binary instructions.
def find_insns_sigs_from_bin(src_sig_list,changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,bin_addr_insn0,bin_addr_insn1,blocks_context0,blocks_context1,block_addrs0,block_addrs1,src_line_map):
 bin_sig_list=[]
 not_found_vul=[]
 not_found_patch=[] 
 #bp()
 #changed_src_lines1,added_src_lines1=find_changed_added_src1(src_sig_list)
 for src_sig in src_sig_list:
  if src_sig.function_name=="idna_init":
   continue 
  elif src_sig.function_name=="free_fixed_hostname":
   continue
  elif src_sig.function_name=="png_handle_iTXt":
   continue
  #if src_sig.function_name=="EC_GROUP_get0_generator":
  # bp()  
  bin_sig,not_found_vul_tmp,not_found_patch_tmp=find_insn_sig_from_bin(src_sig,changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,bin_addr_insn0,bin_addr_insn1,blocks_context0,blocks_context1,block_addrs0,block_addrs1,src_line_map)
  for i in not_found_vul_tmp:
   not_found_vul.append(i)
  for i in not_found_patch_tmp:
   not_found_patch.append(i)
  if bin_sig:#If found bin insns for both vul and patch signature 
   bin_sig_list.append(bin_sig)
 bin_sig_by_func=group_by_func(bin_sig_list)
 #for func in bin_sig_by_func:
 # if has_zero_sig(bin_sig_by_func[func]):
 #  bp()
 return bin_sig_list,not_found_vul,not_found_patch

#Dictionarize the list by function name.
def group_by_func(bin_sig_list):
 result_dict={}
 for sig in bin_sig_list:
  if sig.function_name not in result_dict:
    result_dict[sig.function_name]=[sig]
  else:
    result_dict[sig.function_name].append(sig)
 return result_dict

#Check whether the specific function's signature are all null.
def has_zero_sig(sig_list):
 for sig in sig_list:
  if sig.vul_signature==[] and sig.patch_signature==[]:
   continue
  else:
   return False
 return True

#Find all the changed lines (which are not only addded or deleted) in the patched version. Because if the sig is only an add (in the patched version), we typically want to find a contextual (parent-child) signature. However, if the parent is the changed srcs, we should just skip this added signature because the changed sig should contain the vul signature already. 
#Also, we need to find the added lines in the patched version. Because if there is an added site at patched version, and if it has an added parent, then we should just ignore this added site. Because its parent's signature already reveals contextual information.
def find_changed_added_src1(src_sig_list):
 changed_src_lines=[]
 added_src_lines=[]
 for sig in src_sig_list:
  if sig.vul_signature and sig.patch_signature:#If not add or delete, but is changed sig.
   for src_line in sig.patch_signature:
    changed_src_lines.append(src_line)
  elif (not sig.vul_signature) and sig.patch_signature:#If is added sig.
   for src_line in sig.patch_signature:
    added_src_lines.append(src_line)
 return changed_src_lines,added_src_lines

#For all the src files under this cve folder, we all find its binary instructions.
def find_each_cve(current_cve_path,descending_versions):
 files=os.listdir(current_cve_path)
 two_versions=[]
 #Order two versions path by order
 for each_file in files:
  if os.path.isdir(current_cve_path+"/"+each_file):
   two_versions.append(each_file)
 two_versions=increase_order(two_versions,descending_versions)
 #Process each source file's insn signatures 
 for each_file in files:
  if each_file.endswith(".c_insn_sig.pickle"):
   if "lib557.c" in each_file or "lib1527.c" in each_file:
    continue
   if has_bin_sig(each_file,files):
    print("skip...")
    continue
   extract_each_insn_sig_list(each_file,current_cve_path,two_versions)
  #elif each_file.endswith(".c_struct_sig.pickle"): 
  # if has_bin_sig(each_file,files):
  #  print("skip...")
  #  continue
  # extract_each_struct_sig_list(each_file,current_cve_path,two_versions)

def extract_each_insn_sig_list(each_file,current_cve_path,two_versions):
   print("Processing",current_cve_path,each_file)
   f=open(current_cve_path+"/"+each_file,'rb')
   sig_list=pickle.load(f)
   f.close()
   file_name=each_file.split(".c_insn_sig.pickle")[0]
   old_bin=find_binary(current_cve_path+"/"+two_versions[0],file_name)
   new_bin=find_binary(current_cve_path+"/"+two_versions[1],file_name)
   #if (not os.path.isfile(old_bin)) or (not os.path.isfile(new_bin)):#If .o file not exists. Should be not compilable.
   # continue
   if old_bin==None or new_bin==None:
    return
   source_bin_map0=read_bin_symbol(old_bin)
   source_bin_map1=read_bin_symbol(new_bin)
   if source_bin_map0=={} or source_bin_map1=={}:#If the .o is not well compiled, just skip it.
    return
   proj0=angr.Project(old_bin,load_options={"auto_load_libs":False})
   cfg0=proj0.analyses.CFGFast()
   blocks_addrs0=find_blocks_addrs(proj0,cfg0)
   block_context_dict0=find_blocks_context(proj0,cfg0)
   #cfg0=proj0.analyses.CFGEmulated(keep_state=True)
   bin_addr_insn0=extract_bin_addr_insn(proj0,cfg0)
   proj1=angr.Project(new_bin,load_options={"auto_load_libs":False})
   cfg1=proj1.analyses.CFGFast()
   blocks_addrs1=find_blocks_addrs(proj1,cfg1)
   block_context_dict1=find_blocks_context(proj1,cfg1)
   #cfg1=proj1.analyses.CFGEmulated(keep_state=True)
   bin_addr_insn1=extract_bin_addr_insn(proj1,cfg1)
   src_line_map=map_two_version_c_files_diff(current_cve_path,two_versions,file_name)
   changed_src_lines1,added_src_lines1=find_changed_added_src_by_diff(current_cve_path+"/"+two_versions[0]+'/'+file_name+".c",current_cve_path+"/"+two_versions[1]+'/'+file_name+".c",1)
   bin_sig_list,not_found_vul,not_found_patch=find_insns_sigs_from_bin(sig_list,changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,bin_addr_insn0,bin_addr_insn1,block_context_dict0,block_context_dict1,blocks_addrs0,blocks_addrs1,src_line_map)
   #if "CVE-2015-7981" in current_cve_path:
   # bp()
   write_pickle(bin_sig_list,current_cve_path,"bin_"+file_name)
   if len(not_found_vul):
    not_found_vul=filter_comm_macro(not_found_vul,file_name,current_cve_path+"/"+two_versions[0])
    write_not_found_error(not_found_vul,two_versions[0],current_cve_path,each_file)
   if len(not_found_patch):
    not_found_patch=filter_comm_macro(not_found_patch,file_name,current_cve_path+"/"+two_versions[1])
    write_not_found_error(not_found_patch,two_versions[1],current_cve_path,each_file)


def extract_each_struct_sig_list(each_file,current_cve_path,two_versions):
   print("Processing",current_cve_path,each_file)
   f=open(current_cve_path+"/"+each_file,'rb')
   sig_list=pickle.load(f)
   f.close()
   file_name=each_file.split(".c_struct_sig.pickle")[0]
   old_bin=find_binary(current_cve_path+"/"+two_versions[0],file_name)
   new_bin=find_binary(current_cve_path+"/"+two_versions[1],file_name)
   source_bin_map0=read_bin_symbol(old_bin)
   source_bin_map1=read_bin_symbol(new_bin)

   proj0=angr.Project(old_bin,load_options={"auto_load_libs":False})
   cfg0=proj0.analyses.CFGFast()
   bin_addr_insn0=extract_bin_addr_insn(proj0,cfg0)
   changed_src_lines0,added_src_lines0=find_changed_added_src_by_diff(current_cve_path+"/"+two_versions[0]+'/'+file_name+".c",current_cve_path+"/"+two_versions[1]+'/'+file_name+".c",0)

   proj1=angr.Project(new_bin,load_options={"auto_load_libs":False})
   cfg1=proj1.analyses.CFGFast()
   bin_addr_insn1=extract_bin_addr_insn(proj1,cfg1)
   changed_src_lines1,added_src_lines1=find_changed_added_src_by_diff(current_cve_path+"/"+two_versions[0]+'/'+file_name+".c",current_cve_path+"/"+two_versions[1]+'/'+file_name+".c",1)
   function_names=[]
   for sig in sig_list:
    if sig.function_name not in function_names:
     function_names.append(sig.function_name)
   for function in function_names:
    bin_sig=func_same_src_diff_offset(function,bin_addr_insn0,bin_addr_insn1,source_bin_map0,source_bin_map1,changed_src_lines0,added_src_lines0,changed_src_lines1,added_src_lines1)

#Compare the assembly code of the function's two versions. If we find any structure-related offset that does not exists in both versions, then it is the wanted offset. Specifically, the different offset should exists in the block sharing the same src lines. Because if in changed or added lines, then the instruction is already in a sig.
#def func_same_src_diff_offset(function,bin_addr_insn0,bin_addr_insn1,source_bin_map0,source_bin_map1,changed_src_lines0,added_src_lines0,changed_src_lines1,added_src_lines1):
  

#In order to get all the changed and added site, we diff the two c source codes.
def find_changed_added_src_by_diff(c_path0,c_path1,i):
 added_lines1=[]
 changed_lines1=[]
 diff_result=os.popen("diff "+c_path0+" "+c_path1).read()
 diff_insn_list=construct_diff_insn_list(diff_result) 
 for diff_struct in diff_insn_list:
   if diff_struct.header[0]=='a':
    lines_list1=comma2list(diff_struct.header[i+1])
    for line in lines_list1:
     added_lines1.append(line)
   elif diff_struct.header[0]=='c':
    lines_list=comma2list(diff_struct.header[i+1])
    for line in lines_list:
     changed_lines1.append(line) 
 return changed_lines1, added_lines1


#We map the common lines by their line number in two versions. The key is the patched version's src line number and the value is the vulnerable version's line number. 
def map_two_version_c_files(current_cve_path,two_versions,file_name):
 src_map={}
 command="awk 'FNR==NR{l[$0]=NR; next}; $0 in l{print $0, l[$0], FNR}' "
 vul_c_path=current_cve_path+"/"+two_versions[0]+"/"+file_name+".c"
 patch_c_path=current_cve_path+"/"+two_versions[1]+"/"+file_name+".c"
 command+=vul_c_path+" "
 command+=patch_c_path
 awk_result=os.popen(command).read()
 lines=awk_result.split('\n')
 for line in lines:
  if line=='':
   continue
  tokens=line.split(" ")
  if len(tokens)<2:
   bp()
  vul_src_line=tokens[-2]
  patch_src_line=tokens[-1]
  src_map[patch_src_line]=vul_src_line
 return src_map

#We map the common lines by their line number in two versions. The key is the patched version's src line number and the value is the vulnerable version's line number. In this version function, we use diff's side-by-side flag to match common lines.
def map_two_version_c_files_diff(current_cve_path,two_versions,file_name):
 src_map={}
 vul_line=0
 patch_line=0
 command="diff -y -t "
 vul_c_path=current_cve_path+"/"+two_versions[0]+"/"+file_name+".c"
 patch_c_path=current_cve_path+"/"+two_versions[1]+"/"+file_name+".c"
 command+=vul_c_path+" "
 command+=patch_c_path
 diff_result=os.popen(command).read()
 diff_result1=diff_result.replace("\t","        ")
 lines=diff_result1.split('\n')
 for line in lines:
  if line=='':
   vul_line+=1
   patch_line+=1
   continue
  #if len(line)<=64:
  # bp()
  delimiter=line[64]
  if delimiter=="|":#Denote a change
   vul_line+=1
   patch_line+=1
   src_map[patch_line]=vul_line
   #print("vul_line:",vul_line,"patch_line:",patch_line,"line:",line)
   #bp()
  elif delimiter=='<':#Denote a delete
   vul_line+=1
   #print("vul_line:",vul_line,"patch_line:",patch_line,"line:",line)
   #bp()
  elif delimiter=='>':#Denote an add
   patch_line+=1
   #print("vul_line:",vul_line,"patch_line:",patch_line,"line:",line)
   #bp()
  else:#Same line for both versions
   vul_line+=1
   patch_line+=1
   src_map[patch_line]=vul_line
 #bp()
 return src_map

#For each function's each blocks, we find all its instructions' addresses. 
def find_blocks_addrs(proj,cfg):
 functions=proj.kb.functions.items()
 functions_dict={}
 #bp()
 for func in functions:
  #if 'setcharset'==func[1].name:
  #  bp()
  func_name=func[1].name
  blocks_dict={}
  func_object=cfg.kb.functions.function(addr=func[0])
  for block_addr in func_object.block_addrs:
   block=proj.factory.block(block_addr)
   block_disasm=str(block.disassembly)
   dic=dictize_block_string(block_disasm)
   blocks_dict[normalize_angr_addr2objdump_addr(hex(block_addr))]=[] 
   for addr in dic:
    blocks_dict[normalize_angr_addr2objdump_addr(hex(block_addr))].append(addr)
  if func_name.find(".isra")!=-1:
   func_name=func_name.split(".isra")[0]
  elif func_name.find(".constprop")!=-1:
   func_name=func_name.split(".constprop")[0]
  functions_dict[func_name]=blocks_dict
 return functions_dict
   

def write_not_found_error(not_found_src_insns,version,current_cve_path,each_file):
 if not_found_src_insns:
  f=open(current_cve_path+"/"+"bin_not_found_"+each_file+"_"+version,'w')
  string=""
  for line in not_found_src_insns:
   string+=line[0]+"	"+str(line[1])+"	"+line[2]+"\n"
  f.write(string)
  f.close()

#Read debug symbol from a binary file. We can have a map between each src lines and its binary instruction.
#Note that one src line can corresponds to many basic blocks in objdump.
def read_bin_symbol(binary):
 result=os.popen('objdump -S -l '+binary).read()
 lines=result.split("\n")
 symbol_record_map={}
 for line_index in range(0,len(lines)):
  if lines[line_index].startswith("Disassembly of section .text.unlikely:"):
   lines=lines[:line_index]
   break
 #if "tool_getparam" in binary:
 # bp()
 line_index=0
 while line_index < len(lines):
  #print(lines[line_index])
  #bp()
  #print(line_index)
  if is_src_index_line(lines[line_index]):
   src_line_number=extract_src_line_number(lines[line_index])
   current_record_end=find_current_record_end(lines,line_index+1)
   src_lines,bin_lines=find_src_bin_lines(lines,line_index+1,current_record_end)
   new_record=symbol_record(src_lines,bin_lines)
   src_line_index=int(src_line_number)
   if src_line_index not in symbol_record_map:
    symbol_record_map[src_line_index]=[new_record]
   else:
    symbol_record_map[src_line_index].append(new_record)
   line_index=current_record_end+1
  else:
   line_index+=1
 return symbol_record_map


#For all the cves of a project, we extract all its binary instructions.
def main():
 #cve_path=input("Please enter the root path for all cves:").strip("'")
 #all_versions_record=input("Please enter the path recording all versions:").strip("'")
 cve_path="/home/nuc/Desktop/firmware_cve/dcs-6517_7517"
 all_versions_record="/home/nuc/Desktop/VIVA/openssl-versions"
 f=open(all_versions_record,"r")
 descending_versions=list(filter(None,f.read().split("\n")))
 files=os.listdir(cve_path)
 for cve in files:
   #if cve!="CVE-2016-7056":#For debugging purpose.
   # continue
   if "CVE-2014-8151"==cve or "CVE-2016-9952"==cve or "CVE-2011-3389"==cve or "CVE-2012-0036"==cve or "CVE-2013-0249"==cve or "CVE-2016-8619" ==cve or cve=="CVE-2018-1000005" or cve=="CVE-2019-5481" or cve=="CVE-2014-2522" or cve=="CVE-2016-9953" or cve=="CVE-2013-1960" or cve=="CVE-2016-3945" or cve=="CVE-2016-9536" or cve=="CVE-2008-0891" or cve=="CVE-2018-14879" or cve=="CVE-2018-16301" or cve=="CVE-2011-3974" or cve=="CVE-2015-3395":
    continue
   print("Processing",cve)
   if os.path.isdir(cve_path+"/"+cve):
      current_cve_path=cve_path+"/"+cve
      #if cve=="CVE-2015-2154":
      # bp()
      find_each_cve(current_cve_path,descending_versions)

 
#If the patch is an addition of lines, we cannot find any vul sig directly because there is no src vul sigs. But we can infer contextual differences around the added site. 
def find_add_vul_sig(patch_signature,changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,func_bin_addr_insn0,func_bin_addr_insn1,blocks_context0,blocks_context1,block_addrs0,block_addrs1,src_line_map):
 #if 41 in patch_signature:
 # bp()
 vul_context_sigs=[]
 #Firstly find all the bin insns of all patched src lines.
 patch_insns_addrs=[]
 for line_index in patch_signature:
  bin_addrs1=find_bin_addrs_by_src_line_index(line_index,patch_signature[line_index],source_bin_map1,func_bin_addr_insn1)
  for bin_addr in bin_addrs1:
   patch_insns_addrs.append(bin_addr)
 
 if patch_insns_addrs==[]:#None of the patched src found its bin insns
  print("Not found vul sig:",patch_signature)
  #bp()
  return []
  
 #Secondly find the parent blocks of these patched insns 
 patched_blocks=category_addrs_by_block(patch_insns_addrs,block_addrs1)
 #if patched_blocks==['400000', '27', 'a0', '31', '39', '98']:
 # bp()
 patched_parent_blocks=[]#Record parent blocks for all patched blocks in this signature
 patched_children_blocks=[]#Record children blocks for all patched blocks in this signature. Used when patched_parent_blocks is null.
 for block_addr in patched_blocks:
  parents=blocks_context1[block_addr].predecessors
  for parent_addr in parents:#By default we consider the predecessors to the patched blocks as a context signature.
   #if parent_addr=='120':
   # bp()
   if parent_addr in patched_blocks:#Parent can not be the added if it is one of the added block itself
    continue
   else:
    if parent_addr not in patched_parent_blocks:
     patched_parent_blocks.append(parent_addr)
 if len(patched_parent_blocks)!=0:#Generate signature by parents
  for parent_addr in patched_parent_blocks:
    
    vul_context_sig,patched_context_sig=find_vul_patch_sig_by_p(src_line_map,changed_src_lines1,added_src_lines1,parent_addr,source_bin_map0,source_bin_map1,block_addrs0,block_addrs1,blocks_context0,blocks_context1,func_bin_addr_insn0,func_bin_addr_insn1)
    if vul_context_sig:#If vul site is like changed-->null, and patch site is like changed->added, we dont add. If vul site is like null-->null, patched site is like added-->added, we dont add. Because these two cases can generate sig somewhere else. 
     #bp()
     if vul_context_sig!=None:
      vul_context_sigs.append(vul_context_sig)

 elif len(patched_parent_blocks)==0:#Patched blocks dont have even a single parent, that means it might be added at the beginning of the function. Then we need to find signature by its children.
   for block_addr in patched_blocks:
    children=blocks_context1[block_addr].successors
    for child_addr in children:#Now we consider the successors to the patched blocks as a context signature.
     #if parent_addr=='20':
     # bp()
     if child_addr in patched_blocks:#Children can not be the added if it is one of the added block itself
      continue
     else:
      if child_addr not in patched_children_blocks:
       patched_children_blocks.append(child_addr)
   #bp()
   for child_addr in patched_children_blocks:
    vul_context_sig,patched_context_sig=find_vul_patch_sig_by_c(src_line_map,changed_src_lines1,added_src_lines1,child_addr,source_bin_map0,source_bin_map1,block_addrs0,block_addrs1,blocks_context0,blocks_context1,func_bin_addr_insn0,func_bin_addr_insn1)
    if vul_context_sig!=None:
     vul_context_sigs.append(vul_context_sig)
  
   '''#Find all the patched src lines in parent
   patched_parent_src_lines=find_block_src_lines(source_bin_map1,parent_addr,block_addrs1)
   patched_parent_blocks=find_block_by_src_lines(patched_parent_src_lines,source_bin_map1,block_addrs1)#Because one src lines might exists in many blocks, we need to find all of them for both patched and vul versions.
   patched_context_sig=find_p_c_sig(patched_parent_blocks,block_addrs1,blocks_context1,func_bin_addr_insn1)
   
   #Thirdly find the vul version's corresponding parent blocks as well as their children as a vul contextual signature
   vul_src_lines=find_equivalent_vul_src_lines(patched_parent_src_lines,src_line_map)
   vul_parent_blocks=find_block_by_src_lines(vul_src_lines,source_bin_map0,block_addrs0)
   vul_context_sig=find_p_c_sig(vul_parent_blocks,block_addrs0,blocks_context0,func_bin_addr_insn0)
   #bp()
   #vul_context_sig=filter_common_context_sig(vul_context_sig,patched_context_sig)'''
  
   
 if vul_context_sigs==None:
  bp()
 return vul_context_sigs

#Find sigs in both vul and patch versions from the parent.
def find_vul_patch_sig_by_p(src_line_map,changed_src_lines1,added_src_lines1,parent_addr,source_bin_map0,source_bin_map1,block_addrs0,block_addrs1,blocks_context0,blocks_context1,func_bin_addr_insn0,func_bin_addr_insn1):
  #if parent_addr=='4f9':
  # bp()
  vul_bin_p_blocks,patched_bin_p_blocks=Find_equivalent_block(changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,block_addrs0,block_addrs1,parent_addr,src_line_map)
  if vul_bin_p_blocks==None and patched_bin_p_blocks==None:#Means that the parent is a change src line, we should ignore them as the vul signature exists at the change sig.
   return None, None
  elif vul_bin_p_blocks==None and patched_bin_p_blocks:#Means that the parent is an added src line, we should ignore them as the vul signature exists at the change sig.
   return None, None
  else:#Prents are the same
   vul_context_sig=find_sig_by_p(vul_bin_p_blocks,block_addrs0,blocks_context0,func_bin_addr_insn0)
   patched_context_sig=find_sig_by_p(patched_bin_p_blocks,block_addrs1,blocks_context1,func_bin_addr_insn1)
   return vul_context_sig,patched_context_sig

#Find sigs in both vul and patch versions from the children.
def find_vul_patch_sig_by_c(src_line_map,changed_src_lines1,added_src_lines1,child_addr,source_bin_map0,source_bin_map1,block_addrs0,block_addrs1,blocks_context0,blocks_context1,func_bin_addr_insn0,func_bin_addr_insn1):
  vul_bin_c_blocks,patched_bin_c_blocks=Find_equivalent_block(changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,block_addrs0,block_addrs1,child_addr,src_line_map)
  if vul_bin_c_blocks==None and patched_bin_c_blocks==None:#Means that the children is a change src line, we should ignore them as the vul signature exists at the change sig.
   return None, None
  elif vul_bin_c_blocks==None and patched_bin_c_blocks:#Children is added sig
   #Firstly find the vul bin's first block
   func_first_block0=None
   for block in blocks_context0:
    if blocks_context0[block].predecessors==[]:
     func_first_block0=block
     break
   vul_context_sig=find_sig_by_p([func_first_block0],block_addrs0,blocks_context0,func_bin_addr_insn0)
   patched_context_sig=find_sig_by_c(patched_bin_c_blocks,block_addrs1,blocks_context1,func_bin_addr_insn1) 
   return vul_context_sig,patched_context_sig
  elif len(vul_bin_c_blocks)==0:#Not found the correct corresponding block in vul bin
    return None,None
  elif vul_bin_c_blocks and patched_bin_c_blocks:#Found the two same children on both vul and patch versions
   vul_context_sig=find_sig_by_c(vul_bin_c_blocks,block_addrs0,blocks_context0,func_bin_addr_insn0)
   patched_context_sig=find_sig_by_c(patched_bin_c_blocks,block_addrs1,blocks_context1,func_bin_addr_insn1) 
   return vul_context_sig,patched_context_sig
 
#We find the block in vul version that is equivalent to the patched version block. We return two items, the equivalent vul bin blocks, and all the blocks in the patched version corresponds to the patched src lines. Because one patched src lines can map to multiple bin blocks. 
def Find_equivalent_block(changed_src_lines1,added_src_lines1,source_bin_map0,source_bin_map1,block_addrs0,block_addrs1,patched_block_addr,src_line_map):
   #if patched_block_addr=="172c":
   #  bp()
   #Find all the patched src lines
   patched_src_lines=find_block_src_lines(source_bin_map1,patched_block_addr,block_addrs1)
   for patched_src_line in patched_src_lines:#If the parent src line or child src line is within one of the change src lines, we just ignore them.
    if patched_src_line in changed_src_lines1:#This block has a changed src line
      return None,None
    elif patched_src_line in added_src_lines1:#This block has a added src line
      patched_bin_blocks=find_block_by_src_lines(patched_src_lines,source_bin_map1,block_addrs1)#Because one src lines might exists in many blocks, except the current block.
      return None, patched_bin_blocks 
   #if 2762 in patched_src_lines:
   # bp()
   patched_bin_blocks=find_block_by_src_lines(patched_src_lines,source_bin_map1,block_addrs1)#Because one src lines might exists in many blocks, except the current block.
   
   #Next, find the vul version's corresponding parent blocks as well as their children as a vul contextual signature
   vul_src_lines=find_equivalent_vul_src_lines(patched_src_lines,src_line_map)
   #if 1177 in vul_src_lines:
   # bp()
   vul_bin_blocks=find_block_by_src_lines(vul_src_lines,source_bin_map0,block_addrs0)
   #if "a7a" in vul_bin_blocks:
   # bp()
   return vul_bin_blocks, patched_bin_blocks

main()
