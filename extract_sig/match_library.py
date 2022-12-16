from pdb import set_trace as bp
import angr
from common_library import make_hex, addr2const_string, normalize_address, sub_p_c_sig, p_c_sig
from extract_insn_from_bin_lib import dictize_block_string,normalize_angr_addr2objdump_addr,find_blocks_context

MATCH_LEVEL=3
#We define a three-level matching strategy. Level 1-level 3. 
#1: Level 3 is the most strict one. Need to check whether patch exists. For parent-child structure, need to confirm both parents and children exist. For each instruction, strictly check operator and operands syntactically equivalent.
#2: Level 2 is mild. Does not need to check patch exists. Do not need both parents and children exists for parent-child structure. 
#3: Level 3 is the most fuzzing one. This is good for dealing with subtle binary code changes due to compiling/configuration/version. For each instruction, do not need strictly operator and operand all equal. INsteand we calculate the similarity between two instructions. Thus we tolerate subtle inferences such as different registers between two similar instructions.



#Sometimes the block context might only has parent or child because the context is at function beginning/end. Thus we only match one block of the block context.
def find_matched_one_block(sig_block,blocks_asm):
 max_insn_num=0
 max_block_addr=""
 for block_addr in blocks_asm:
   matched_insn_num=block_contain_consecutive_insns(sig_block,blocks_asm[block_addr])
   if matched_insn_num>max_insn_num:
    max_insn_num=matched_insn_num
    max_block_addr=block_addr
 return max_block_addr,max_insn_num

#Extract each function's each blocks' asm, as well as each functions' context information into a dictionary.
def process_bin(bin_path):
 print("process_bin:",bin_path)
 proj=None
 cfg=None
 try:
  proj=angr.Project(bin_path,load_options={"auto_load_libs":False})
  cfg=proj.analyses.CFGFast()
 except:
  bp()
 functions=proj.kb.functions.items()
 functions_asms={}
 for func in functions:
  func_name=func[1].name 
  #if func_name=="ftp_parse_url_path":
  # bp()
  if func_name.find(".isra")!=-1:
   func_name=func_name.split(".isra")[0]
  elif func_name.find(".constprop")!=-1:
   func_name=func_name.split(".constprop")[0]
  blocks_dict={}
  func_object=cfg.kb.functions.function(addr=func[0])
  strings_refs=[]
  try:
   strings_refs=func_object.string_references(vex_only=True)
  except:
   strings_refs=[]
  strings_refs=make_hex(strings_refs)
  #if func[1].name=="PKCS7_dataInit":
  # bp()
  for block_addr in func_object.block_addrs:
   #if hex(block_addr)=='0x5071c0':
   #  bp()
   block_asm=[]
   block=proj.factory.block(block_addr)
   block_disasm=str(block.disassembly)
   block_disasm=addr2const_string(block_disasm,strings_refs)
   if block_disasm=="":#For the null blocks that misidentified by angr as block
    continue
   dic=dictize_block_string(block_disasm)
   #if is_align_block(dic):
   # continue
   for key in dic:
    block_asm.append(dic[key])
   normalized_block=normalize_address(block_asm)
   blocks_dict[normalize_angr_addr2objdump_addr(hex(block_addr))]=normalized_block
  functions_asms[func_name]=blocks_dict
 block_context_dict=find_blocks_context(proj,cfg) 
 return functions_asms,block_context_dict

#Just simply search the blocks for existence of instructions in sig. The sig can contain many blocks.
def search_block_with_insns(sig,blocks_asm):
 matched_addr=[]
 total_matched_insns_num=0
 for block in sig:
  max_matched_insns_num=0
  max_matched_addr=""
  for block1 in blocks_asm:
    #if block==[' ldr r0, [r6]', ' add r3, r8, r0', ' cmp r3, ip', ' blt #0x400754'] and block1=='4baaa0':
    # bp()
    matched_insns_num=find_matched_block_insns(block,blocks_asm[block1])
    if matched_insns_num>max_matched_insns_num:
     max_matched_insns_num=matched_insns_num
     max_matched_addr=block1
  matched_addr.append(max_matched_addr)
  total_matched_insns_num+=max_matched_insns_num
 return total_matched_insns_num, matched_addr

def search_block_context_with_context(sig,p_sig,blocks_asm,block_context): 
 matched_block_asms=[]#Record the matched asms
 matched_block_addrs=[]#Record the matched blocks addrs
 total_matched_insn=0#Record the matched insns num
 for item in sig:#One item corresponds to one src added site. Because one src line may map to multiple blocks, each item has many p_c_sig structure.
  for p_c in item:
   if p_c.c==None:
     bp()
   if len(p_c.p)==0:#Only has child, probably child is the beginning of a function
    matched_c,matched_c_num=find_matched_one_block(p_c.c,blocks_asm)
    #for matched_c, matched_c_num in zip(matched_cs,matched_c_nums)
    if matched_c!="":
     matched_block_asm_tmp=blocks_asm[matched_c]
     for insn in matched_block_asm_tmp:
      matched_block_asms.append(insn)
     matched_block_addrs.append(matched_c)
     total_matched_insn+=matched_c_num
    
   elif len(p_c.c)==0:#Only has parent, probably parent is the end of a function
    matched_p,matched_p_num=find_matched_one_block(p_c.p,blocks_asm)
    #for matched_p,matched_p_num in zip(matched_ps,matched_p_nums):
    if matched_p!="":
     matched_block_asm_tmp=blocks_asm[matched_p]
     for insn in matched_block_asm_tmp:
      matched_block_asms.append(insn)
     matched_block_addrs.append(matched_p)
     total_matched_insn+=matched_p_num
    
   else:#Has both parent and children
    matched_ps,matched_p_nums,matched_cs,matched_c_nums=find_matched_block_context(p_c,blocks_asm,block_context)
    for matched_p, matched_p_num in zip(matched_ps,matched_p_nums):
     if matched_p!="":
      matched_block_asm_tmp=blocks_asm[matched_p]
      for insn in matched_block_asm_tmp:
       matched_block_asms.append(insn)
      total_matched_insn+=matched_p_num
      matched_block_addrs.append(matched_p)
     
    for matched_c, matched_c_num in zip(matched_cs,matched_c_nums):
     if matched_c!="":
      matched_block_asm_tmp=blocks_asm[matched_c]
      for insn in matched_block_asm_tmp:
       matched_block_asms.append(insn)
      total_matched_insn+=matched_c_num
      matched_block_addrs.append(matched_c)
 
 #for block in matched_block:
 # total_matched_insn+=matched_block[block]
 #if p_sig==[[[' mov rax, qword ptr [rbx + 0x80]', ' lea rdx, [rax - 4]', ' cmp rax, rdx', 'jb addr']], [[' lea rax, [r12 + 8]', ' cmp rdx, rax', 'jb addr']], [[' mov edx, dword ptr [r12 + 8]']]]:
 # bp()
 if MATCH_LEVEL==3:
  if patch_exists(p_sig,matched_block_asms):
   return 0,[]

 #return total_matched_insn,matched_block_addrs
 return total_matched_insn, matched_block_addrs

def search_block_context_with_context_vis(sig,p_sig,blocks_asm,block_context): 
 interprete_sig=[]#copy paste the original signature with interpretation of matched insns
 matched_block_asms=[]#Record the matched asms
 matched_block_addrs=[]#Record the matched blocks addrs
 total_matched_insn=0#Record the matched insns num
 for item in sig:#One item corresponds to one src added site. Because one src line may map to multiple blocks, each item has many p_c_sig structure.
  new_item=[]
  for p_c in item:
   matched_c=""
   matched_c_num=None
   matched_p=""
   matched_c_num=None
   new_p_c=p_c_sig(None,None)
   if p_c.c==None:
     bp()
   if len(p_c.p)==0:#Only has child, probably child is the beginning of a function
    matched_c,matched_c_num=find_matched_one_block(p_c.c,blocks_asm)
    #for matched_c, matched_c_num in zip(matched_cs,matched_c_nums)
    '''if matched_c!="":
     matched_block_asm_tmp=blocks_asm[matched_c]
     for insn in matched_block_asm_tmp:
      matched_block_asms.append(insn)
     matched_block_addrs.append(matched_c)
     total_matched_insn+=matched_c_num
     new_p_c.c=(p_c.c,matched_c,matched_block_asm_tmp)'''
    if matched_c!="": 
        matched_block_asms,total_matched_insn,matched_block_addrs, matched_block_asm_tmp=new_p_c_append_convention(matched_c, blocks_asm, matched_block_asms, matched_c_num, total_matched_insn, matched_block_addrs, each_c)
        new_p_c.c=(each_c,matched_c,matched_block_asm_tmp)
    else:
       new_p_c.c=(each_c,"",[])
   elif len(p_c.c)==0:#Only has parent, probably parent is the end of a function
    matched_p,matched_p_num=find_matched_one_block(p_c.p,blocks_asm)
    #for matched_p,matched_p_num in zip(matched_ps,matched_p_nums):
    '''if matched_p!="":
     matched_block_asm_tmp=blocks_asm[matched_p]
     for insn in matched_block_asm_tmp:
      matched_block_asms.append(insn)
     matched_block_addrs.append(matched_p)
     total_matched_insn+=matched_p_num
     
     new_p_c.p=(p_c.p,matched_p,matched_block_asm_tmp)'''
    if matched_p!="": 
        matched_block_asms,total_matched_insn,matched_block_addrs, matched_block_asm_tmp=new_p_c_append_convention(matched_p, blocks_asm, matched_block_asms, matched_p_num, total_matched_insn, matched_block_addrs, each_p)
        new_p_c.p=(each_p,matched_p,matched_block_asm_tmp)
    else:
       new_p_c.p=(each_p,"",[])
   else:#Has both parent and children
    matched_ps,matched_p_nums,matched_cs,matched_c_nums=find_matched_block_context(p_c,blocks_asm,block_context)
    new_p_c.p=[]
    new_p_c.c=[]
    if type(p_c.p[0])==str:#parent is a single block
      if len(matched_ps)==0:
        matched_p = ""
        matched_p_num = None
      else:
       matched_p =  matched_ps[0]
       matched_p_num = matched_p_nums[0]
      each_p = p_c.p
      '''if matched_p!="":
        matched_block_asm_tmp=blocks_asm[matched_p]
        for insn in matched_block_asm_tmp:
         matched_block_asms.append(insn)
        total_matched_insn+=matched_p_num
        matched_block_addrs.append(matched_p)
        new_p_c.p=(each_p,matched_p,matched_block_asm_tmp)'''
      if matched_p!="": 
        matched_block_asms,total_matched_insn,matched_block_addrs, matched_block_asm_tmp=new_p_c_append_convention(matched_p, blocks_asm, matched_block_asms, matched_p_num, total_matched_insn, matched_block_addrs, each_p)
        new_p_c.p=(each_p,matched_p,matched_block_asm_tmp)
      else:
       new_p_c.p=(each_p,"",[])
    elif type(p_c.p[0])==list:#parent is many blocks
     for matched_p, matched_p_num, each_p in zip(matched_ps,matched_p_nums,p_c.p):
      '''if matched_p!="":
       matched_block_asm_tmp=blocks_asm[matched_p]
       for insn in matched_block_asm_tmp:
        matched_block_asms.append(insn)
       total_matched_insn+=matched_p_num
       matched_block_addrs.append(matched_p)
       new_p_c.p.append((each_p,matched_p,matched_block_asm_tmp))'''
      if matched_p!="": 
        matched_block_asms,total_matched_insn,matched_block_addrs, matched_block_asm_tmp=new_p_c_append_convention(matched_p, blocks_asm, matched_block_asms, matched_p_num, total_matched_insn, matched_block_addrs, each_p)
        new_p_c.p.append((each_p,matched_p,matched_block_asm_tmp))
      else:
       new_p_c.p.append((each_p,"",[]))
    if type(p_c.c[0])==str:#child is a single block
      if len(matched_cs)==0:
        matched_c = ""
        matched_c_num = None
      else:
       matched_c =  matched_cs[0]
       matched_c_num = matched_c_nums[0]
      each_c = p_c.c
      '''if matched_c!="":
        matched_block_asm_tmp=blocks_asm[matched_c]
        for insn in matched_block_asm_tmp:
         matched_block_asms.append(insn)
        total_matched_insn+=matched_c_num
        matched_block_addrs.append(matched_c)
        new_p_c.c=(each_c,matched_c,matched_block_asm_tmp)'''
      if matched_c!="": 
       matched_block_asms,total_matched_insn,matched_block_addrs, matched_block_asm_tmp=new_p_c_append_convention(matched_c, blocks_asm, matched_block_asms, matched_c_num, total_matched_insn, matched_block_addrs, each_c)
       new_p_c.c=(each_c,matched_c,matched_block_asm_tmp)
      else:
       new_p_c.c=(each_c,"",[])
    elif type(p_c.c[0])==list:#child is many blocks  
     for matched_c, matched_c_num, each_c in zip(matched_cs,matched_c_nums, p_c.c):
      '''if matched_c!="": 
       matched_block_asm_tmp=blocks_asm[matched_c]
       for insn in matched_block_asm_tmp:
        matched_block_asms.append(insn)
       total_matched_insn+=matched_c_num
       matched_block_addrs.append(matched_c)
       new_p_c.c.append((each_c,matched_c,matched_block_asm_tmp))'''
      if matched_c!="": 
       matched_block_asms,total_matched_insn,matched_block_addrs, matched_block_asm_tmp=new_p_c_append_convention(matched_c, blocks_asm, matched_block_asms, matched_c_num, total_matched_insn, matched_block_addrs, each_c)
       new_p_c.c.append((each_c,matched_c,matched_block_asm_tmp))
      else:
       new_p_c.c.append((each_c,"",[]))
    
   new_item.append(new_p_c)  
  interprete_sig.append(new_item)
 #for block in matched_block:
 # total_matched_insn+=matched_block[block]
 #if p_sig==[[[' mov rax, qword ptr [rbx + 0x80]', ' lea rdx, [rax - 4]', ' cmp rax, rdx', 'jb addr']], [[' lea rax, [r12 + 8]', ' cmp rdx, rax', 'jb addr']], [[' mov edx, dword ptr [r12 + 8]']]]:
 # bp()
 if MATCH_LEVEL==3:
  if patch_exists(p_sig,matched_block_asms):
   return 0,[]

 #return total_matched_insn,matched_block_addrs
 return total_matched_insn, interprete_sig

def new_p_c_append_convention(matched_blk, blocks_asm, matched_block_asms, matched_blk_num, total_matched_insn, matched_block_addrs, each_blk):
       matched_block_asm_tmp=blocks_asm[matched_blk]
       for insn in matched_block_asm_tmp:
        matched_block_asms.append(insn)
       total_matched_insn+=matched_blk_num
       matched_block_addrs.append(matched_blk)
       return matched_block_asms,total_matched_insn,matched_block_addrs, matched_block_asm_tmp

#For a list consisting of sub_p_c_sig and list of asms, we find each item's existence in blocks_asm and block_context.
def search_block_many_change(sig,p_sig,blocks_asm,block_context):
 total_matched_insn_num=0
 dbg_matched_block=[]
 matched_block_asm=[]
 for item in sig:
  if type(item)==sub_p_c_sig:
   tmp_matched_insn_num, dbg_tmp_matched_block=find_one_sub_p_c_one_func(item,blocks_asm,block_context)
   total_matched_insn_num+=tmp_matched_insn_num
   for block in dbg_tmp_matched_block:
     dbg_matched_block.append(block)
  elif type(item)==list:
    tmp_matched_insn_num, dbg_tmp_matched_block=search_block_with_insns([item],blocks_asm)
    total_matched_insn_num+=tmp_matched_insn_num
    for block in dbg_tmp_matched_block:
     dbg_matched_block.append(block)
 dbg_matched_block = list(dict.fromkeys(dbg_matched_block))
 dbg_matched_block = list(filter(None, dbg_matched_block))
 for block in dbg_matched_block:
  matched_block_asm_tmp=blocks_asm[block]
  for insn in matched_block_asm_tmp:
   matched_block_asm.append(insn)
 if MATCH_LEVEL==3:
  if patch_exists(p_sig,matched_block_asm):
    return 0,[]
 #return total_matched_insn_num,dbg_matched_block
 return total_matched_insn_num, dbg_matched_block

#For a list consisting of sub_p_c_sig and list of asms, we find each item's existence in blocks_asm and block_context.
def search_block_many_change_vis(sig,p_sig,blocks_asm,block_context):
 interpret_sig=[]#copy paste the original signature with interpretation of matched insns
 total_matched_insn_num=0
 dbg_matched_block=[]
 matched_block_asm=[]
 for item in sig:
  if type(item)==sub_p_c_sig:
   tmp_matched_insn_num,dbg_tmp_matched_block=find_one_sub_p_c_one_func(item,blocks_asm,block_context)
   total_matched_insn_num+=tmp_matched_insn_num
   for block in dbg_tmp_matched_block:
     dbg_matched_block.append(block)
   
   tmp_matched_blocks_asm=[]
   for block in dbg_tmp_matched_block:
    tmp_matched_block_asm=[]
    matched_block_asm_tmp=blocks_asm[block]
    for insn in matched_block_asm_tmp:
     tmp_matched_block_asm.append(insn)
    tmp_matched_blocks_asm.append(tmp_matched_block_asm)
   new_item=(item,dbg_tmp_matched_block,tmp_matched_blocks_asm)
  elif type(item)==list:
    tmp_matched_insn_num, dbg_tmp_matched_block=search_block_with_insns([item],blocks_asm)
    total_matched_insn_num+=tmp_matched_insn_num
    for block in dbg_tmp_matched_block:
     dbg_matched_block.append(block)
    tmp_matched_block_asm=[]
    for block in dbg_tmp_matched_block:
     if block=="":#Not found similar block
      pass
     else:#Not found similar block
      matched_block_asm_tmp=blocks_asm[block]
      for insn in matched_block_asm_tmp:
       tmp_matched_block_asm.append(insn)
    new_item=(item,dbg_tmp_matched_block,tmp_matched_block_asm)
  interpret_sig.append(new_item)
 dbg_matched_block = list(dict.fromkeys(dbg_matched_block))
 dbg_matched_block = list(filter(None, dbg_matched_block))
 for block in dbg_matched_block:
  matched_block_asm_tmp=blocks_asm[block]
  for insn in matched_block_asm_tmp:
   matched_block_asm.append(insn)
 if MATCH_LEVEL==3:
  if patch_exists(p_sig,matched_block_asm):
    return 0,[]
 #return total_matched_insn_num,dbg_matched_block
 return total_matched_insn_num, interpret_sig

def try_find_one_sub_p_c_one_func(sig,p_sig,blocks_asm,block_context):
 matched_block_asm=[]
 tmp_matched_insn_num,dbg_tmp_matched_block=find_one_sub_p_c_one_func(sig,blocks_asm,block_context)
 total_matched_insn_num=tmp_matched_insn_num
 dbg_tmp_matched_block = list(dict.fromkeys(dbg_tmp_matched_block))
 dbg_tmp_matched_block = list(filter(None, dbg_tmp_matched_block))
 for block in dbg_tmp_matched_block:
  matched_block_asm_tmp=blocks_asm[block]
  for insn in matched_block_asm_tmp:
   matched_block_asm.append(insn)
 if MATCH_LEVEL==3:
  if patch_exists(p_sig,matched_block_asm):
    return 0,[]
 return tmp_matched_insn_num,dbg_tmp_matched_block

def try_find_one_sub_p_c_one_func_vis(sig,p_sig,blocks_asm,block_context):
 interpret_sig=[]#copy paste the original signature with interpretation of matched insns
 matched_blocks_asm=[]#Used only for patch detecting
 tmp_matched_insn_num,dbg_tmp_matched_block=find_one_sub_p_c_one_func(sig,blocks_asm,block_context)
 total_matched_insn_num=tmp_matched_insn_num
 dbg_tmp_matched_block = list(dict.fromkeys(dbg_tmp_matched_block))
 #dbg_tmp_matched_block = list(filter(None, dbg_tmp_matched_block))
 tmp_matched_blocks_asm=[]#Used only for sig generation
 for block in dbg_tmp_matched_block:
  if block=="":
   tmp_matched_blocks_asm.append([""])
   continue
  tmp_matched_block_asm=[]
  matched_block_asm_tmp=blocks_asm[block]
  for insn in matched_block_asm_tmp:
   matched_blocks_asm.append(insn)
   tmp_matched_block_asm.append(insn)
  tmp_matched_blocks_asm.append(tmp_matched_block_asm)
 interpret_sig=(sig,dbg_tmp_matched_block,tmp_matched_blocks_asm)
 if MATCH_LEVEL==3:
  if patch_exists(p_sig,matched_blocks_asm):
    return 0,[]
 return tmp_matched_insn_num,interpret_sig

#Define how we consider a sub_p_c context match is a good context match.
def good_sub_context_match(total_matched_insn_num,max_matched_insn_num,matched_insn):
 if MATCH_LEVEL==3:
  return (total_matched_insn_num>max_matched_insn_num and matched_insn>0)
 else:
  return total_matched_insn_num>max_matched_insn_num

#Either parents or children shall be a single block. Thus we firstly find that block. THen we match the parents/ children.
def find_one_sub_p_c_one_func(sub_p_c,blocks_asm,block_context):
 if len(sub_p_c.p)==1:#If is single-parent connected by multiple children
  max_matched_insn_num=0
  max_matched_p_block=""
  max_matched_c_addr=[]
  max_matched_c_insn=[]
  for block in blocks_asm:
   #if block=="1034":
   # bp()
   total_matched_insn_num=0
   p_matched_num=find_matched_block_insns(sub_p_c.p,blocks_asm[block])
   total_matched_insn_num+=p_matched_num
   if p_matched_num>0:
    children=block_context[block].successors
    tmp_matched_addr,tmp_matched_insn,matched_insn=match_blocks_to_blocks(sub_p_c.c,blocks_asm,children)
    total_matched_insn_num+=matched_insn
    if good_sub_context_match(total_matched_insn_num,max_matched_insn_num,matched_insn):#Make sure both parent and children has match
      max_matched_insn_num=total_matched_insn_num
      max_matched_p_block=block
      max_matched_c_addr=tmp_matched_addr
      max_matched_c_insn=tmp_matched_insn
  all_matched_block=max_matched_c_addr
  all_matched_block.insert(0,max_matched_p_block)
  return max_matched_insn_num,all_matched_block
 elif len(sub_p_c.c)==1:#If is single-child connected by multiple parents
  max_matched_insn_num=0
  max_matched_c_block=""
  max_matched_p_addr=[]
  max_matched_p_insn=[]
  for block in blocks_asm:
   total_matched_insn_num=0
   c_matched_num=find_matched_block_insns(sub_p_c.c,blocks_asm[block])
   total_matched_insn_num+=c_matched_num
   if c_matched_num>0:
    parents=block_context[block].predecessors
    tmp_matched_addr,tmp_matched_insn,matched_insn=match_blocks_to_blocks(sub_p_c.p,blocks_asm,parents)
    total_matched_insn_num+=matched_insn
    if good_sub_context_match(total_matched_insn_num,max_matched_insn_num,matched_insn):#Make sure both parent and children has match
      max_matched_insn_num=total_matched_insn_num
      max_matched_c_block=block
      max_matched_p_addr=tmp_matched_addr
      max_matched_p_insn=tmp_matched_insn
  all_matched_block=max_matched_p_addr
  all_matched_block.insert(0,max_matched_c_block)
  return max_matched_insn_num,all_matched_block
 else:
  return 0,[]
  #bp()

#For matching children to children or parents to parents in a block context. Return the best one-block to one-block match. blocks0 is a list of blocks, blocks1_asm is one function's all blocks' asm. children is that a list of block address.
def match_blocks_to_blocks(blocks0,blocks1_asm,block_addr_list):
 tmp_matched_addr=[]
 tmp_matched_insn=[]
 for block0 in blocks0:#Next match the children blocks to blocks
   max_matched_addr=""
   max_matched_insn_num=0
   for block1 in block_addr_list:
     #print("match_blocks_to_blocks try block1:",block1)
     #if block1=='69':
     # bp()
     matched_num=block_contain_consecutive_insns(block0,blocks1_asm[block1])
     if matched_num>max_matched_insn_num:
      max_matched_insn_num=matched_num
      max_matched_addr=block1
   tmp_matched_addr.append(max_matched_addr)
   tmp_matched_insn.append(max_matched_insn_num) 
 
 matched_insn=0
 for insn in tmp_matched_insn:
  matched_insn+=insn
 
 return tmp_matched_addr,tmp_matched_insn,matched_insn

#For the consecutive insns in block, we find how many of them can be found in block1
def find_matched_block_insns(block,block1):
  matched_insns_num=0
  for consecutive_insns in block:
   tmp_matched_num=block_contain_consecutive_insns(consecutive_insns,block1)
   matched_insns_num+=tmp_matched_num
  return matched_insns_num

#Calculate how much insns within the consecutive instructions are matched. We dictate the following rule to reduce false positives: If the matched insn are all conditional jump or directly jump, then the mateched insns equals zero. Only if the matched insn has at least one insn is not the conditional jump or directly jump, the matched insn is as it is.
def block_contain_consecutive_insns(consecutive_insns,block):
 matched_insn=0
 dbg_matched_insns=[]
 #if is_align_block(block):
 # return 0
 has_non_j_insn=False
 if MATCH_LEVEL==3 or MATCH_LEVEL==2:
  matched_insn, dbg_matched_insns, has_non_j_insn=strict_match_insn(consecutive_insns, block, dbg_matched_insns, has_non_j_insn, matched_insn)
 elif MATCH_LEVEL==1:
  matched_insn, dbg_matched_insns, has_non_j_insn=fuzz_match_insn(consecutive_insns, block, dbg_matched_insns, has_non_j_insn, matched_insn)
  '''if consecutive_insns[insn_index] in block:
   dbg_matched_insns.append(insn_index)
   if not consecutive_insns[insn_index].strip().startswith("j"):
    has_non_j_insn=True
   matched_insn+=1'''
 #if matched_insn>0:
  #for index in range(0,len(consecutive_insns)):
   #if index in dbg_matched_insns:
   # print("matched:",consecutive_insns[index])
   #else:
   # print("        ",consecutive_insns[index])
  #print("") 
 if has_non_j_insn==False and len(consecutive_insns)>1:
  matched_insn=0
 return matched_insn 

#In L3 and L2, we need to match both operator and operands perfectly to regard it a match
def strict_match_insn(consecutive_insns, block, dbg_matched_insns, has_non_j_insn, matched_insn):
 for insn_index in range(0,len(consecutive_insns)):
  if consecutive_insns[insn_index] in block:
    dbg_matched_insns.append(insn_index)
    if not consecutive_insns[insn_index].strip().startswith("j"):
     has_non_j_insn=True
    matched_insn+=1
 return matched_insn, dbg_matched_insns, has_non_j_insn

  
#In L1, we need the operator to match (or one is a substring of another e.g., ldr & ldrh). As to the 
def fuzz_match_insn(consecutive_insns, block, dbg_matched_insns, has_non_j_insn, matched_insn):   
  list_block_insns=[]#Each insn in the block is listized
  for block_insn in block:
   list_block_insns.append(listize_insn(block_insn))
  for insn_index in range(0,len(consecutive_insns)):
   tmp_max_match=0#Record the max match score of the current insn in consecutive_insns with some insn in the block
   max_index=-1#Record the max match insn index in the block

   listized_insn=listize_insn(consecutive_insns[insn_index])
   operator=listized_insn[0]
   for block_insn_index in range(0,len(list_block_insns)):
    if list_block_insns[block_insn_index][0]==operator or list_block_insns[block_insn_index][0].startswith(operator) or operator.startswith(list_block_insns[block_insn_index][0]):#If operator equal, or is included in each other, we consider it as initially same
      set1=set(list_block_insns[block_insn_index][1:])
      set2=set(listized_insn[1:])
      jac_sim=len(set1.intersection(set2)) *1.0/ len(set1.union(set2))
      if jac_sim>tmp_max_match:
        tmp_max_match=jac_sim
        max_index=block_insn_index
   if tmp_max_match>0:
    matched_insn+=tmp_max_match
    dbg_matched_insns.append(insn_index)
    has_non_j_insn=True
  return matched_insn, dbg_matched_insns, has_non_j_insn

#For a string of assembly instruction, we make it a list. e.g., asr r1, [r5], #0x1 --> [asr, r1, [, r5, ], #0x1] 
def listize_insn(insn): 
 result_list=[]
 items=insn.split()
 for item in items:
  if item.startswith("["):
   result_list.append("[")
   result_list.append(item[1:])
  elif item.startswith("{"):
   result_list.append("{")
   result_list.append(item[1:])
  elif item.endswith("]"):
   result_list.append(item[:-1])
   result_list.append("]")
  elif item.endswith("],"):
   result_list.append(item[:-2])
   result_list.append("],")
  elif item.endswith("}"):
   result_list.append(item[:-1])
   result_list.append("}")
  elif item.endswith("},"):
   result_list.append(item[:-2])
   result_list.append("},")
  else:
   result_list.append(item)
 return result_list
 
 

#p_sig is a list of asm insns, matched_block_asms is also a list of vul asm insns. We check whether the p_sig exists in matched_block_asms.
def patch_exists(p_sig,matched_block_asms):
 flattened_p_sig=flatten_sig(p_sig)
 if len(flattened_p_sig)==0:
  return False
 for sig in flattened_p_sig:
   if sig in matched_block_asms:
     continue
   else:
     return False
 return True

#Make a list like [[['',''],['','']]] into a list like ['','','','']
def flatten_sig(sig):
 result=[]
 for element in sig:
  if type(element)==list:
    result_tmp=flatten_sig(element)
    for item in result_tmp:
     result.append(item)
  elif type(element)==str:
    result.append(element)
 return result

#Define how we consider a context match is a good match
def good_context_match(tmp_context_matched_insn,max_context_matched_insn,tmp_matched_insn):
 if MATCH_LEVEL==3:
  return (tmp_context_matched_insn>max_context_matched_insn and all_above_zero(tmp_matched_insn))
 else:
  return tmp_context_matched_insn>max_context_matched_insn

def find_matched_block_context(p_c,blocks_asm,block_context):
 matched_ps=[]
 matched_p_nums=[]
 matched_cs=[]
 matched_c_nums=[]
 if is_single_block(p_c.p):#If the parent is single but children is many 
  max_context_matched_insn=0
  max_p_matched_addr=[]
  max_p_matched_insn=[]
  max_c_matched_addr=[]
  max_c_matched_insn=[]
  #if p_c.p==[' test rax, rax', ' je 0x400056'] and p_c.c==[[' mov rsi, r13', ' mov rdi, rbp', ' xor r15d, r15d', ' call 0x500008'], [' mov esi, 0x2e', ' mov rdi, rbp', ' mov r12, rax', ' call 0x500000']]:
  # bp()
  #print("sig parent is:",p_c.p)
  for block in blocks_asm:#First match single parent
    #print("find_matched_block_context try block:",block)
    p_matched_num=block_contain_consecutive_insns(p_c.p,blocks_asm[block])
    #if block=='44a51a' and (p_c.p==[' test rax, rax', ' je 0x400056']) and (p_c.c==[[' mov rsi, r13', ' mov rdi, rbp', ' xor r15d, r15d', ' call 0x500008'], [' mov esi, 0x2e', ' mov rdi, rbp', ' mov r12, rax', ' call 0x500000']]):
    #  bp()
    #if p_matched_num>0:
    tmp_p_matched_insn=p_matched_num
    children=block_context[block].successors
    tmp_matched_addr,tmp_matched_insn,matched_insn=match_blocks_to_blocks(p_c.c,blocks_asm,children)
    
    #Calculate this block context match insn number
    tmp_context_matched_insn=tmp_p_matched_insn+matched_insn

    #Record the current max block context match
    if good_context_match(tmp_context_matched_insn,max_context_matched_insn,tmp_matched_insn):
      max_context_matched_insn=tmp_context_matched_insn
      max_p_matched_addr=[block]
      max_p_matched_insn=[tmp_p_matched_insn]
      max_c_matched_addr=tmp_matched_addr
      max_c_matched_insn=tmp_matched_insn
    #print("___________________________________________")

  return  max_p_matched_addr, max_p_matched_insn, max_c_matched_addr, max_c_matched_insn    
 elif is_single_block(p_c.c):#If child is single but parent is many
  max_context_matched_insn=0
  max_p_matched_addr=[]
  max_p_matched_insn=[]
  max_c_matched_addr=[]
  max_c_matched_insn=[]
  for block in blocks_asm:#First match single child
    c_matched_num=block_contain_consecutive_insns(p_c.c,blocks_asm[block])
    if c_matched_num>0:
     tmp_c_matched_insn=c_matched_num
     parents=block_context[block].predecessors
     tmp_matched_addr,tmp_matched_insn,matched_insn=match_blocks_to_blocks(p_c.p,blocks_asm,parents)
    
     #Calculate this block context match insn number
     tmp_context_matched_insn=tmp_c_matched_insn+matched_insn

     #Record the current max block context match
     if good_context_match(tmp_context_matched_insn,max_context_matched_insn,tmp_matched_insn):
      max_context_matched_insn=tmp_context_matched_insn
      max_c_matched_addr=[block]
      max_c_matched_insn=[tmp_c_matched_insn]
      max_p_matched_addr=tmp_matched_addr
      max_p_matched_insn=tmp_matched_insn
  return  max_p_matched_addr, max_p_matched_insn, max_c_matched_addr, max_c_matched_insn  
 return None,None,None,None

#Check whether the parent/child in the block context is a single block or a list of blocks.
def is_single_block(p_or_c):
 if type(p_or_c[0])==list:
  return False
 elif type(p_or_c[0])==str:
  return True

#Make sure all parents/children block has a match.
def all_above_zero(tmp_matched_insn):
 for i in tmp_matched_insn:
  if i==0:
   return False
 return True
