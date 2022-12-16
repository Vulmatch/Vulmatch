import networkx as nx
from transform_sig import read_bin_sig
from match_library import process_bin
import matplotlib.pyplot as plt

#func_sig is the transformed signature. total_sig_insn_num is the total number of insns this signature has. blocks_asm is one function's each blocks' assembly. block_context is the function's context information.
#Returns true if the candidate function is considered as vulmerable/patched.
def match_one_sig_one_func_visual(vul_sigs,patch_sigs,total_sig_insn_num,blocks_asm,block_context):
 matched_insn_num=0#Record how many insns in the sig is matched.
 intprt_sigs=[]#Translated and interpreted vul signatures.
 for sig,p_sig in zip(vul_sigs,patch_sigs):
  if sig.sig_type=="delete":
   tmp_matched_insn_num, matched_addrs=search_block_with_insns(sig.sig,blocks_asm)
   matched_asm=[]
   for block in matched_addrs:
    matched_block_asm=[]
    for insn in blocks_asm[block]:
     matched_block_asm.append(insn)
    matched_asm.append(matched_block_asm)
   intprt_sig=(sig.sig, matched_addrs, matched_asm)
   matched_insn_num+=tmp_matched_insn_num
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,tmp_matched_insn_num))
  elif sig.sig_type=="add":
   tmp_matched_insn_num, intprt_sig=search_block_context_with_context_vis(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,tmp_matched_insn_num))
   print(tmp_matched_insn_num,"matched")
  elif sig.sig_type=="many_change":
   tmp_matched_insn_num, intprt_sig=search_block_many_change_vis(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,tmp_matched_insn_num))
  elif sig.sig_type=="one_change":
   tmp_matched_insn_num, intprt_sig=try_find_one_sub_p_c_one_func_vis(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,tmp_matched_insn_num))
 print("matched_insn_num:",matched_insn_num,"total_sig_insn_num:",total_sig_insn_num)
 sig_sim=matched_insn_num*1.0/total_sig_insn_num
 #if sig_similarity >=similarity_threshold:
 #if sig_sim>0:
 # bp()
 return sig_sim, intprt_sigs

#From a sig list of a .o file, we use each function's sig to match sigs in the binary.
def match_functions_sigs_one_bin_visual(functions_sigs,functions_asms,block_context_dict):
  funcs_result_dict={}
  for function in functions_sigs:
   sig=functions_sigs[function]
   func_result_dict={}
   for function1 in functions_asms:
    function_asms=functions_asms[function1]
    function_context=block_context_dict[function1]
    #if function=="operate_do" and function1=="operate_do":
    # bp()
    #print(function," vs ",function1)
    if sig.total_vul_insn_number==0:
     bp()
    sim,intprt_sigs=match_one_sig_one_func_visual(sig.transformed_vul_sigs,sig.transformed_patch_sigs,sig.total_vul_insn_number,function_asms,function_context)
    func_result_dict[function1]=(sim,intprt_sigs)
   funcs_result_dict[function]=func_result_dict
  return funcs_result_dict


def draw_matched(sim,intprt_sigs,selected_sig_func,selected_o_file_func):
 sig_index=0
 for sig in intprt_sigs:
  if sig.sig_type=="delete":
   draw_delete(sig.sig,sig_index)
  elif sig.sig_type=="add":
   draw_add(sig.sig,sig_index)
  elif sig.sig_type=="many_change":
   draw_many_change(sig.sig,sig_index)
  elif sig.sig_type=="one_change":
   draw_one_change(sig.sig,sig_index)
  sig_index+=1
 
def draw_delete(sig,sig_index):
 G = nx.DiGraph()#sig's graph
 G1= nx.DiGraph()#o file func's graph
 labeldict={}
 labeldict1={}
 raw_sig, matched_addrs, matched_asm=sig
 block_index=0
 
 #draw graph of signature and matched .o file function
 for block in raw_sig:
  G.add_node(block_index)
  G1.add_node(block_index)
  block_asm=""
  for consecutive_insns in block:
   for insn in consecutive_insns:
     block_asm+=insn+"\n"
  labeldict[block_index] = block_asm

  block_asm1=""
  for block in matched_asm:
   for insn in block:
    block_asm1+=insn+"\n"
  labeldict1[block_index] = block_asm1
  block_index+=1

 draw_epilogue(G,G1,labeldict,labeldict1,sig_index)

def draw_epilogue(G,G1,labeldict,labeldict1,sig_index):
 pos = nx.spring_layout(G)
 pos1 = nx.spring_layout(G1)
 
 subax0 = plt.subplot(121)
 nx.draw_networkx(G, pos, labels=labeldict, node_size=100, with_labels = True, node_color='b', node_shape='s')

 subax1 = plt.subplot(122)
 nx.draw_networkx(G1, pos1, labels=labeldict1, node_size=100, with_labels = True, node_color='r', node_shape='s')
  
 plt.savefig("sig"+sig_index+".png")

def draw_add(sig,sig_index):
 G = nx.DiGraph()#sig's graph
 G1= nx.DiGraph()#o file func's graph
 labeldict={}
 labeldict1={}
 block_index=0
 appended_addr=[]#used to record the address already in the graph. Do this do deduplicate same nodes in the graph
 for item in sig:
   for p_c in item:
     if len(p_c.p)==0:#Only has child, probably child is the beginning of a function
      raw_c, matched_c_addrs, matched_c_asms=p_c.c
      G, G1, labeldict, labeldict1, block_index=add_node_in_graph(G, G1, appended_addr, raw_c, matched_c_addrs, matched_c_asms, labeldict, labeldict1, block_index)
     elif len(p_c.c)==0:#Only has parent, probably parent is the end of a function
      G, G1, labeldict, labeldict1, block_index=add_node_in_graph(G, G1, appended_addr, raw_p, matched_p_addrs, matched_p_asms, labeldict, labeldict1, block_index)
     else:#Has both parent and children
      raw_c, matched_c_addrs, matched_c_asms=p_c.c
      raw_p, matched_p_addrs, matched_p_asms=p_c.p
      p_nodes_start_index=block_index
      G, G1, labeldict, labeldict1, block_index=add_node_in_graph(G, G1, appended_addr, raw_c, matched_c_addrs, matched_c_asms,  labeldict, labeldict1, block_index)
      p_nodes_end_index=block_index-1
      c_nodes_start_index=block_index
      G, G1, labeldict, labeldict1, block_index=add_node_in_graph(G, G1, appended_addr, raw_p, matched_p_addrs, matched_p_asms, labeldict, labeldict1, block_index)
      c_nodes_end_index=block_index-1
      G,G1=add_edges_in_graph(G,G1,p_nodes_start_index,p_nodes_end_index,c_nodes_start_index,c_nodes_end_index)
 draw_epilogue(G,G1,labeldict,labeldict1,sig_index) 

def add_edges_in_graph(G,G1,p_nodes_start_index,p_nodes_end_index,c_nodes_start_index,c_nodes_end_index):
  for p_index in range(p_nodes_start_index,p_nodes_end_index+1):
   for c_index in range(c_nodes_start_index,c_nodes_end_index+1):
    G.add_edge(p_index, c_index)
    G1.add_edge(p_index, c_index)
  return G,G1

def add_node_in_graph(G, G1, appended_addr,raw_blocks, matched_blk_addrs, matched_blk_asms, labeldict,labeldict1,block_index):
 for matched_blk_addr, raw_block,matched_blk_asm in zip(matched_blk_addrs,raw_blocks, matched_blk_asms):#matched blocks should have the same order as the sig block because of our agorithm.
  if matched_blk_addr not in appended_addr: 
        appended_addr.append(matched_blk_addr)
        G.add_node(block_index)
        block_asm=""
        for consecutive_insns in raw_block:
         for insn in consecutive_insns:
          block_asm+=insn+"\n"
        labeldict[block_index] = block_asm
        G1.add_node(block_index)
        block_asm1=""
        for insn in matched_blk_asm:
         block_asm1+=insn+"\n"
        labeldict1[block_index] = block_asm1
        block_index+=1
 return G, G1, labeldict, labeldict1, block_index

def draw_many_change(sig,sig_index):
 G = nx.DiGraph()#sig's graph
 G1= nx.DiGraph()#o file func's graph
 labeldict={}
 labeldict1={}
 block_index=0
 appended_addr=[]#used to record the address already in the graph. Do this do deduplicate same nodes in the graph
 for item in sig:
   new_item,matched_block_addr,matched_block_asms=item
   if type(new_item)==sub_p_c_sig:
     if len(new_item.p)==1:#If is single-parent connected by multiple children
       c_start_index=block_index
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, new_item.c, matched_blk_addrs[1:], matched_block_asms[1:], labeldict, labeldict1, block_index)
       c_end_index=block_index-1
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, new_item.p, matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       p_index=block_index-1
       G,G1=add_edges_in_graph(G,G1,p_index,p_index,c_start_index,c_end_index)     
     elif len(sub_p_c.c)==1:#If is single-child connected by multiple parents
       p_start_index=block_index
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, new_item.p, matched_blk_addrs[1:], matched_block_asms[1:], labeldict, labeldict1, block_index)
       p_end_index=block_index-1
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, new_item.c, matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       c_index=block_index-1
       G,G1=add_edges_in_graph(G,G1,p_start_index,p_end_index,c_index,c_index)    
   elif type(new_item)==list:
      for block,block1,asm in zip(new_item,matched_block_addr,matched_block_asms):
        if block1 not in appended_addr: 
         G.add_node(block_index)
         G1.add_node(block_index)
         appended_addr.append(block1)

         block_asm=""
         for consecutive_insns in block:
          for insn in consecutive_insns:
           block_asm+=insn+"\n"
         labeldict[block_index] = block_asm

         block_asm1=""
         for consecutive_insns in asm:
          for insn in consecutive_insns:
           block_asm1+=insn+"\n"
         labeldict1[block_index] = block_asm1
         block_index+=1
 draw_epilogue(G,G1,labeldict,labeldict1,sig_index)

def draw_one_change(sig,sig_index):
 G = nx.DiGraph()#sig's graph
 G1= nx.DiGraph()#o file func's graph
 labeldict={}
 labeldict1={}
 block_index=0
 appended_addr=[]#used to record the address already in the graph. Do this do deduplicate same nodes in the graph
 raw_sig,matched_block_addrs,matched_block_asms=sig
 if len(raw_sig.p)==1:#If is single-parent connected by multiple children
       c_start_index=block_index
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, raw_sig.c, matched_blk_addrs[1:], matched_block_asms[1:], labeldict, labeldict1, block_index)
       c_end_index=block_index-1
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, new_item.p, matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       p_index=block_index-1
       G,G1=add_edges_in_graph(G,G1,p_index,p_index,c_start_index,c_end_index)    
 elif len(sub_p_c.c)==1:#If is single-child connected by multiple parents
       p_start_index=block_index
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, raw_sig.p, matched_blk_addrs[1:], matched_block_asms[1:], labeldict, labeldict1, block_index)
       p_end_index=block_index-1
       G, G1, labeldict, labeldict1, block_index = add_node_in_graph(G, G1, appended_addr, new_item.c, matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       c_index=block_index-1
       G,G1=add_edges_in_graph(G,G1,p_start_index,p_end_index,c_index,c_index) 
 draw_epilogue(G,G1,labeldict,labeldict1,sig_index)

def visualize():
 bin_sig_path=input("Please enter the bin_sig path:").strip("'")
 o_file_path=input("PLease enter the .o file path:").strip("'")
 functions_sigs=read_bin_sig(sig_list_path)
 functions_asms,block_context_dict=process_bin(bin_path)
 #result=match_functions_sigs_one_bin_visual(functions_sigs,functions_asms,block_context_dict)
 
 
 print("signature file contains functions:")
 i=0
 for func in result:
  print(i,func)
  i+=1
 sig_func_index=input("Please enter the function in signature file:").strip("'")
 selected_sig_func=list(result)[int(sig_func_index)]

 print("o file file contains functions:")
 i=0
 func0=list(result)[0]
 for func in result[func0]:
  print(i,func)
  i+=1
 o_func_index=input("Please enter the function in .o file file:").strip("'")
 selected_o_file_func=list(result)[int(o_func_index)]
 
 sig=functions_sigs[selected_sig_func]
 function_asms=functions_asms[selected_o_file_func]
 function_context=block_context_dict[selected_o_file_func]
 sim,intprt_sigs=match_one_sig_one_func_visual(sig.transformed_vul_sigs,sig.transformed_patch_sigs,sig.total_vul_insn_number,function_asms,function_context)

 draw_matched(sim,intprt_sigs,selected_sig_func,selected_o_file_func)
 
