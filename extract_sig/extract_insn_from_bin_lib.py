import os
from pdb import set_trace as bp
import re
from string_util import delete_comments
from common_library import p_c_sig,addr2const_string,make_hex,insn_normalize_address

class block_context:#Each such record records one source code line and its corresponding binary instructions. The source code lines can be many because objdump shows a context sometimes. But the last line in the showed source instructions always points to the source code line number.
    def __init__(self, predecessors,successors):
        self.predecessors = predecessors
        self.successors=successors



def category_addrs_by_block(patch_insns_addrs,block_addrs1):
 blocks_addrs=[]
 for insn_addr in patch_insns_addrs:
  for block in block_addrs1:
   if insn_addr in block_addrs1[block]:
    if block not in blocks_addrs:
     blocks_addrs.append(block)
    break
 return blocks_addrs

def find_blocks_context(proj,cfg):
 functions=proj.kb.functions.items()
 functions_dict={}
 for func in functions:
  blocks_dict={}
  func_name=func[1].name
  #if 'ossl_connect_step1'==func[1].name:
  #  bp()
  func_object=cfg.kb.functions.function(addr=func[0])
  for block_addr in func_object.block_addrs:
   parent_context=[]
   children_context=[]
   block=cfg.model.get_any_node(block_addr)
   #parents=block.predecessors#This gives the wrong control flow
   parents=cfg.graph.predecessors(block)#This gives the right control flow
   #if block_addr==0x4046fb:
   # bp()
   for parent in parents:
    #if parent==0x4046ed and block_addr==0x4046fb:
    # bp()
    if parent.addr not in func_object.block_addrs:#We only consider parent block within function
     continue
    parent_context.append(normalize_angr_addr2objdump_addr(hex(parent.addr)))
    #if '20' in parent_context:
    # bp()
   #children=block.successors#This gives the wrong control flow
   children=cfg.graph.successors(block)#This gives the right control flow
   for child in children:
    if child.addr not in func_object.block_addrs:#We only consider children block within function
     continue
    children_context.append(normalize_angr_addr2objdump_addr(hex(child.addr)))
   context=block_context(parent_context,children_context)
   blocks_dict[normalize_angr_addr2objdump_addr(hex(block_addr))]=context
  if func_name.find(".isra")!=-1:
   func_name=func_name.split(".isra")[0]
  elif func_name.find(".constprop")!=-1:
   func_name=func_name.split(".constprop")[0]
  functions_dict[func_name]=blocks_dict
 return functions_dict
    

#Filter out the same instructions and only reserve the diffent ones.
def filter_same_bin_insn(vul_bin_insns,patch_bin_insns):
  print("vul_bin_insns",vul_bin_insns)
  print("patch_bin_insns",patch_bin_insns)
  vul_diff_insns=list(set(vul_bin_insns)-set(patch_bin_insns))
  patch_diff_insns=list(set(patch_bin_insns)-set(vul_bin_insns))
  return vul_diff_insns,patch_diff_insns

#Because for example, in objdump, the address 0x189 can be 0x500189 in angr.
def normalize_angr_addr2objdump_addr(addr):
  
  if addr.startswith("0x"):
   addr=addr[2:]
  else:
   bp()
  if '0' not in addr:#does not has 0 in the string
   return addr
  elif has_no_middle_0(addr):#Like 0x452000
   return addr
  else:#Has middle 0 such as 0x40052ad
   normalized_address=""
   first_zero_index=-1
   #Find first 0
   for index in range(0,len(addr)):
    if addr[index]=="0":
     first_zero_index=index
     break

   zero_end_index=-1
   #Find 0..0 end index
   for index in range(first_zero_index,len(addr)):
    if addr[index]!='0':
     zero_end_index=index-1
     break
   if zero_end_index==-1:#The addr is like 0x400000
    return '0'
   normalized_address=addr[zero_end_index+1:]
   return normalized_address
  
def has_no_middle_0(addr):
 first_zero=addr.find('0')
 for index in range(first_zero,len(addr)):
   if addr[index]!='0':
     return False
 return True

#THe disasm is like '0x40047b:\tmov\tedx, 3\n0x400480:\tmov\tesi, ">>\n"\n0x400485:\tmov\trdi, rbx\n0x400488:\tcall\t0x4000b0'. There is string within it. We need to split by \n symbol, and ignore the \n symbol in strings.
def split_disasm(block_disasm):
 cut_index=[-1]#Record where shall we cut the string
 for i in range(0,len(block_disasm)):
  if block_disasm[i:i+4]=="\n0x4" or block_disasm[i:i+4]=="\n0x5":
   cut_index.append(i)
 cut_index.append(len(block_disasm))
 cutted=[]
 for i in range(0,len(cut_index)-1):
  start=cut_index[i]+1
  end=cut_index[i+1]
  cutted.append(block_disasm[start:end])
 return cutted

#Process the string to make it an address-instruction dictionary.
def dictize_block_string(block_disasm):
 dic={}
 lines=split_disasm(block_disasm)
 #if '"' in block_disasm:
 # bp()
 for line in lines:
  addr=line.split(":")[0]
  normalized_address=normalize_angr_addr2objdump_addr(addr)
  insn=line.split(":")[1]
  insn=insn.replace("\t"," ")
  dic[normalized_address]=insn
 return dic

#For one function, extract a dictionary of addresses and insns.
def extract_one_func_addr_insn(func_object,proj,strings_refs):
  addr_insn={}
  for block_addr in func_object.block_addrs:
   #if block_addr==0x4007f6:
   # bp()
   block=proj.factory.block(block_addr)
   #bp()
   block_disasm=str(block.disassembly)
   block_disasm=addr2const_string(block_disasm,strings_refs)
   dic=dictize_block_string(block_disasm)
   for addr in dic:
    addr_insn[addr]=insn_normalize_address(dic[addr])
  return addr_insn

#Return a dictionary, each key is a function name, the value is a dictionary. The value dictionary has keys with all the addresses its function contains, values are the addresses' corresponding disassembly code. The address should be hex and should not have 0x as prefix.
def extract_bin_addr_insn(proj,cfg):
 bin_addr_insn={}
 functions=proj.kb.functions.items()
 for func in functions:
  #if 'dsa_sign_setup'==func[1].name:
  #  bp()
  func_object=cfg.kb.functions.function(addr=func[0])
  strings_refs=[]
  try:
   strings_refs=func_object.string_references(vex_only=True)
  except:
   strings_refs=[]
  strings_refs=make_hex(strings_refs)
  func_dict=extract_one_func_addr_insn(func_object,proj,strings_refs)  
  func_name=func[1].name
  if func_name.find(".isra")!=-1:
   func_name=func_name.split(".isra")[0]
  elif func_name.find(".constprop")!=-1:
   func_name=func_name.split(".constprop")[0]
  bin_addr_insn[func_name]=func_dict
 return bin_addr_insn

#For each line in source code, find the corresponding binary instruction. Note that one src line can corresponds to different blocks in the objdump.
def find_bin_addrs_by_src_line_index(line_index,src_line_str,source_bin_map,bin_func_addr_insn):
 
  #Firstly get the binary line indexes.
  if line_index in source_bin_map:#If the line number is in objdump symbol, thus is in the map, directly get the binary line indexes.
   bin_indexes=[]
   for record in source_bin_map[line_index]:
    for bin_line in record.bin_lines:
     bin_indexes.append(bin_line)
  else:#If the line number is not in objdump symbol. 
   #bp()
   print("not found in objdump:",line_index,src_line_str)
   return []
  #Secondly get the binary line index corresponding binary instructions.
  
  return bin_indexes
 
#Already know the binary instruction address, get their disassembly.
def get_bin_insns_by_bin_line_index(bin_func_addr_insn,bin_indexes):
  #if bin_indexes==['1df', '1e1', '1e7', '1ee']:
  #   bp()
  bin_insns={}
  for bin_index in bin_indexes:
   bin_insn=find_bin_insn_with_addr(bin_index,bin_func_addr_insn)
   if bin_insn:
    bin_insns[bin_index]=bin_insn
  return bin_insns


def find_bin_insn_with_addr(bin_index,bin_func_addr_insn):
   #if bin_index=='860':
   # bp()
  if bin_index in bin_func_addr_insn:#In .o file, has such address
   return bin_func_addr_insn[bin_index]
  else:#In .o file, no such address. Maybe such address is added by objdump mistakenly or angr fails to get such address.
   return None

#For each line in source code, find the corresponding binary instruction. Note that one src line can corresponds to different blocks in the objdump.
def find_bin_insn_by_src_line_index(line_index,src_line_str,source_bin_map,bin_func_addr_insn):
  bin_insns_list=[]#For recording multiple times the same src exists
  #if line_index==262:
  # bp()
  #Firstly get the binary line indexes.
  if line_index in source_bin_map:#If the line number is in objdump symbol, thus is in the map, directly get the binary line indexes.
   bin_indexes=[]
   for record in source_bin_map[line_index]:
    for bin_line in record.bin_lines:
     bin_indexes.append(bin_line)
    bin_insns=get_bin_insns_by_bin_line_index(bin_func_addr_insn,bin_indexes) 
    bin_insns_list.append(bin_insns)
    bin_indexes=[]
  else:#If the line number is not in objdump symbol. 
   #bp()
   print("not found in objdump:",line_index,src_line_str)
   #if line_index==261:
   # bp()
   return []
  #Secondly get the binary line index corresponding binary instructions.
  #if 'bfe' in bin_indexes:
  # bp()
  
  return bin_insns_list

#For each signature's bin codes, we group them by same block. THe bin_insns is in the form of: [[map1,map2,...],[map1,map2,...]]
def group_by_block(bin_insns,block_addrs):
 blocks={}
 #bp()
 for each_map in bin_insns:
   splitted_blocks=find_affliate_block(each_map,block_addrs)
   for splitted_block in splitted_blocks:
     if splitted_block not in blocks:
      blocks[splitted_block]={}
      blocks[splitted_block][splitted_blocks[splitted_block][0]]=splitted_blocks[splitted_block][1]
     else:
      blocks[splitted_block][splitted_blocks[splitted_block][0]]=splitted_blocks[splitted_block][1]
 
 return blocks
   
#For a src sig, the bin insutrctions still might come from more than one blocks. We split them by blocks.
def find_affliate_block(each_map,block_addrs):
 splitted_blocks={}
 for insn_addr in each_map:
 
  for block in block_addrs:
    if insn_addr in block_addrs[block]:
     if block not in splitted_blocks:
      splitted_blocks[block]=(insn_addr,[each_map[insn_addr]])
     else:
      splitted_blocks[block][1].append(each_map[insn_addr])
     break
  
 return splitted_blocks


   
  

#If the line is like: /home/nuc/Downloads/vulnerable_projects/curl/curl-7.61.1/src/tool_msgs.c:41, which denotes the src line number,
def is_src_index_line(line_string):
 tail=line_string.split("/")[-1]
 if re.match("[a-zA-Z0-9_\-]+.c:[0-9]+",tail):
  return True
 else:
  return False

def extract_src_line_number(line_string):
 line_number=line_string.split(".c:")[1]
 if line_number.find(" ")!=-1:
  line_number=line_number.split(" ")[0]
 return line_number

#Find the end of current source-code-line-number, source code, and binary code record end line.
def find_current_record_end(lines,start_line):
 for line_index in range(start_line,len(lines)):
  if is_src_index_line(lines[line_index]):
   return line_index-1
 return len(lines)-1

#Know the current source-code-line-number, source code, and binary code record end line, find the src code and binary code respectively.
def find_src_bin_lines(lines,start_line,end_line):
 src_lines=[]
 bin_lines=[]
 for line_index in range(start_line,end_line+1):
  if is_binary_line(lines[line_index]):
   bin_lines.append(lines[line_index].split(":")[0].strip())
  else:
   src_lines.append(lines[line_index])
 return src_lines,bin_lines
  
#If the line is like:  105:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
def is_binary_line(line_string):
 
 if re.match("[0-9a-f]+:",line_string.strip()):
  return True
 else:
  return False

#For the not found lines, we filter out comment liens, macros, and meaning less lines such as "}", "else{", etc.
def filter_comm_macro(not_found,file_name,version_path):
 filtered=[]
 record_path=version_path+"/"+file_name+".c_comment_macro.txt"
 f=open(record_path,'r')
 content=f.read()
 lines=content.split("\n")
 comment_lines=list_it(lines[0].split("comment_lines:")[1])
 macro_lines=list_it(lines[1].split("macro_lines:")[1])
 for line in not_found:
  if (line[1]-1) in comment_lines or (line[1]-1) in macro_lines:
    continue
  elif is_meaningless_line(line[2]):
    continue
  else:
    filtered.append(line)
 return filtered
 
def is_meaningless_line(line_string):
 line_string=delete_comments(line_string).strip()
 if line_string=="{" or line_string=="}" or re.match("else[\s]+{",line_string) or line_string=="":
  return True
 else: return False
 
 
def list_it(list_string):
 result_list=[]
 if list_string=="[]":
  return []
 list_string=list_string.replace("[","")
 list_string=list_string.replace("]","")
 items=list_string.split(",")
 for item in items:
  result_list.append(int(item.strip()))
 return result_list

#Check bin_xxx_insn_sig.pickle exists.
def has_bin_sig(each_file,files):
 if each_file.endswith("insn_sig.pickle"):
  file_name=each_file.split(".c_insn_sig.pickle")[0]
  for i in files:
   if i=="bin_"+file_name+"_insn_sig.pickle":
    return True
  return False
 elif each_file.endswith("struct_sig.pickle"):
  file_name=each_file.split(".c_struct_sig.pickle")[0]
  for i in files:
   if i=="bin_"+file_name+"_struct_sig.pickle":
    return True
  return False

#Find the .o file contating file_name.
def find_binary(version_path,file_name):
 files=os.listdir(version_path)
 for each_file in files:
  if each_file.find(file_name+".o")!=-1:
   return version_path+"/"+each_file


def find_bin_context(parent_blocks,block_context):
   context_sig=[]
   for parent_block in parent_blocks:
    children_blocks=block_context[parent_block].successros
    for children_block in children_blocks:
     p_block_disasm=str(parent_block.disassembly)
     c_block_disasm=str(children_block.disassembly)
     p_dic=dictize_block_string(p_block_disasm)
     p_block_insns=[]
     for addr in p_dic:
      p_block_insns.append(p_dic[addr])
     c_dic=dictize_block_string(c_block_disasm)
     c_block_insns=[]
     for addr in c_dic:
      c_block_insns.append(c_dic[addr])
     context_sig.append(p_block_insns,c_block_insns)
   return context_sig

#Have the block, now we find all the corresponding srcs lines wihtin the block.
def find_block_src_lines(source_bin_map,block_addr,block_addrs):
 found_src_lines=[]
 current_block_addrs=block_addrs[block_addr]
 for insn_addr in current_block_addrs:#For each bin insn in the query block
  for src_line in source_bin_map:#We try to find the query block's insn whether exists in some src line's bin insns.
   src_bin_lines=[]#Record one src line all bins 
   for src_duplicate in source_bin_map[src_line]:#Because one src lines can map to multiple blocks
    for bin_addr in src_duplicate.bin_lines:
     src_bin_lines.append(bin_addr)
   if insn_addr in src_bin_lines:#If 
    found_src_lines.append(src_line)
    break
 found_src_lines = list(dict.fromkeys(found_src_lines))
 return found_src_lines

#Have the src lines, find the block its corresponding bin insns dwells in.
def find_block_by_src_lines(src_lines,source_bin_map,block_addrs):
 blocks=[]
 for line in src_lines:
  if line not in source_bin_map:
   continue
  for src_duplicate in source_bin_map[line]:#Because one src line can map to multiple blocks
   bin_addrs=[]#One src-bin pair's all bin addrs
   for bin_addr in src_duplicate.bin_lines:
    bin_addrs.append(bin_addr)

   for bin_addr in bin_addrs:#For each bin addr in one src-bin pair insn,
    for block in block_addrs:#we search a block it dwells in.
     if bin_addr in block_addrs[block]:
      if block not in blocks:
       blocks.append(block)
 return blocks

#Find parent-children context from parent as a signature.
def find_sig_by_p(parent_blocks,block_addrs,block_context,func_bin_addr_insn):
  sigs=[]
  #bp()
  for parent in parent_blocks:
   p_disasm=get_disasm_of_block(block_addrs[parent],func_bin_addr_insn)
   children_addrs=block_context[parent].successors
   c_disasms=[]
   for child in children_addrs:
    c_disasm=get_disasm_of_block(block_addrs[child],func_bin_addr_insn)
    c_disasms.append(c_disasm)
   sigs.append(p_c_sig(p_disasm,c_disasms))
  return sigs

#Find parent-children context from children as a signature.
def find_sig_by_c(children_blocks,block_addrs,block_context,func_bin_addr_insn):
  sigs=[]
  #bp()
  for child in children_blocks:
   c_disasm=get_disasm_of_block(block_addrs[child],func_bin_addr_insn)
   parents_addrs=block_context[child].predecessors
   p_disasms=[]
   for parent in parents_addrs:
    p_disasm=get_disasm_of_block(block_addrs[parent],func_bin_addr_insn)
    p_disasms.append(p_disasm)
   sigs.append(p_c_sig(p_disasms,c_disasm))
  return sigs
  
#For each insn in the block, find its disasm.
def get_disasm_of_block(block_addrs,func_bin_addr_insn):
 disasm={}
 disasm[block_addrs[0]]=[]
 for addr in block_addrs:
   disasm[block_addrs[0]].append(func_bin_addr_insn[addr])
 return disasm

def find_equivalent_vul_src_lines(patched_src_lines,src_line_map):
  vul_lines=[]
  for line in patched_src_lines:
    vul_lines.append(src_line_map[line])
  return vul_lines

def filter_common_context_sig(vul_context_sig,patched_context_sig):
 filtered_vul_sig=[]
 for sig0 in vul_context_sig:
  p_is_same=False
  c_is_same=False
  common_sig=False
  for sig1 in patched_context_sig:
   if sig0.p_disasm==sig1.p_disasm:
    p_is_same=True
   for child_block_disasm in sig0.c_disasms:
     if child_block_disasm in sig1.c_disasms:
      continue
     else:#different c_disasms
      break
   c_is_same=True
   if p_is_same and c_is_same:
    common_sig=True
    break
  if common_sig:
   continue
  else:
   filtered_vul_sig.append(sig0)
 return  filtered_vul_sig
  
 
