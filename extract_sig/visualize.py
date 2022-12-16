import networkx as nx
from transform_sig import read_bin_sig, transformed_sig
from match_library import process_bin, search_block_context_with_context_vis, search_block_with_insns, search_block_many_change_vis, try_find_one_sub_p_c_one_func_vis
import matplotlib.pyplot as plt
from pdb import set_trace as bp
from common_library import sub_p_c_sig

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
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,(tmp_matched_insn_num,sig.insn_number)))
  elif sig.sig_type=="add":
   tmp_matched_insn_num, intprt_sig=search_block_context_with_context_vis(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,(tmp_matched_insn_num,sig.insn_number)))
   print(tmp_matched_insn_num,"matched")
  elif sig.sig_type=="many_change":
   tmp_matched_insn_num, intprt_sig=search_block_many_change_vis(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,(tmp_matched_insn_num,sig.insn_number)))
  elif sig.sig_type=="one_change":
   tmp_matched_insn_num, intprt_sig=try_find_one_sub_p_c_one_func_vis(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
   intprt_sigs.append(transformed_sig(sig.sig_type,intprt_sig,(tmp_matched_insn_num,sig.insn_number)))
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
   draw_delete(sig.sig, sig_index,sim, sig.sig_type, sig.insn_number[0], sig.insn_number[1], selected_sig_func,selected_o_file_func)
  elif sig.sig_type=="add":
   draw_add(sig.sig,sig_index,sim, sig.sig_type, sig.insn_number[0], sig.insn_number[1], selected_sig_func,selected_o_file_func)
  elif sig.sig_type=="many_change":
   draw_many_change(sig.sig,sig_index,sim, sig.sig_type, sig.insn_number[0], sig.insn_number[1], selected_sig_func,selected_o_file_func)
  elif sig.sig_type=="one_change":
   draw_one_change(sig.sig,sig_index,sim, sig.sig_type, sig.insn_number[0], sig.insn_number[1], selected_sig_func,selected_o_file_func)
  sig_index+=1
 
def draw_delete(sig,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func,selected_o_file_func):
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
 draw_epilogue(G,G1,labeldict,labeldict1,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func)

def draw_epilogue(G,G1,labeldict,labeldict1,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func):
 pos = nx.planar_layout(G)
 pos1 = nx.planar_layout(G1)
 
 fig=plt.figure(figsize=(10,10))
 fig.suptitle("All signatures similarity score:"+str(sim)+"\n"+"Current signature type:"+sig_type+"\n"+"Current signature matched instructions:"+str(sig_matched_insns)+" in a total instructions of:"+str(sig_all_insns), fontsize=13)
 subax0 = plt.subplot(121)
 subax0.set_title("sig func:"+selected_sig_func,fontsize=13)
 nx.draw_networkx(G, pos, font_size=13, labels={}, node_size=50, with_labels = True, node_color='g', node_shape='s')
 subax0.spines['top'].set_visible(False)
 subax0.spines['right'].set_visible(False)
 subax0.spines['left'].set_visible(False)
 subax0.spines['bottom'].set_visible(False)
 
 subax1 = plt.subplot(122)
 subax1.set_title("query func:"+selected_o_file_func,fontsize=13)
 subax1.spines['top'].set_visible(False)
 subax1.spines['right'].set_visible(False)
 subax1.spines['left'].set_visible(False)
 subax1.spines['bottom'].set_visible(False)
 nx.draw_networkx(G1, pos1, font_size=13, labels={}, node_size=50, with_labels = True, node_color='r', node_shape='s')
 
 '''fig, axs = plt.subplots(1,2,figsize=(20,10))
 fig.suptitle("All signatures similarity score:"+str(sim)+"\n"+"Current signature type:"+sig_type+"\n"+"Current signature matched instructions:"+str(sig_matched_insns)+" in a total instructions of:"+str(sig_all_insns), fontsize=10)
 nx.draw_networkx(G, pos, ax=axs[0], font_size=10, labels=labeldict, node_size=50, with_labels = True, node_color='g', node_shape='s')
 nx.draw_networkx(G1, pos1, ax=axs[1], font_size=10, labels=labeldict1, node_size=50, with_labels = True, node_color='r', node_shape='s')'''
 plt.savefig("sig"+str(sig_index)+".pdf")

def draw_add(sig,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func):
 G = nx.DiGraph()#sig's graph
 G1= nx.DiGraph()#o file func's graph
 labeldict={}
 labeldict1={}
 block_index=0
 appended_addr=[]#used to record the address already in the graph. Do this do deduplicate same nodes in the graph
 for item in sig:
   for p_c in item:
     if len(p_c.p)==0:#Only has child, probably child is the beginning of a function
      if len(p_c.c)==0:
        bp()
      raw_c, matched_c_addrs, matched_c_asms=p_c.c
      assert(len(matched_c_addrs)==1)
      G, G1, labeldict, labeldict1, block_index, exist_block_index=add_node_in_graph(G, G1, appended_addr, raw_c, matched_c_addrs[0], matched_c_asms[0], labeldict, labeldict1, block_index)
     elif len(p_c.c)==0:#Only has parent, probably parent is the end of a function
      raw_p, matched_p_addrs, matched_p_asms=p_c.p
      assert(len(matched_p_addrs)==1)
      G, G1, labeldict, labeldict1, block_index, exist_block_index=add_node_in_graph(G, G1, appended_addr, raw_p, matched_p_addrs[0], matched_p_asms[0], labeldict, labeldict1, block_index)
     else:#Has both parent and children
      
      #Add children into graph
      c_nodes_block_indexes=[]#record all childrens' block_index
      if type(p_c.c)==tuple:#child is a single block
       raw_c, matched_c_addrs, matched_c_asms=p_c.c
       G, G1, labeldict, labeldict1, block_index, exist_block_index=add_node_in_graph(G, G1, appended_addr, raw_c, matched_c_addrs, matched_c_asms,  labeldict, labeldict1, block_index)
       c_nodes_block_indexes.append(exist_block_index)
      elif type(p_c.c)==list:#child is many blocks
       for raw_c, matched_c_addrs, matched_c_asms in p_c.c:
        G, G1, labeldict, labeldict1, block_index, exist_block_index=add_node_in_graph(G, G1, appended_addr, raw_c, matched_c_addrs, matched_c_asms,  labeldict, labeldict1, block_index)
        c_nodes_block_indexes.append(exist_block_index)
      
      #Add parents into graph
      p_nodes_block_indexes=[]#record all parents' block_index
      if type(p_c.p)==tuple:#parent is a single block
       raw_p, matched_p_addrs, matched_p_asms=p_c.p
       G, G1, labeldict, labeldict1, block_index, exist_block_index=add_node_in_graph(G, G1, appended_addr, raw_p, matched_p_addrs, matched_p_asms, labeldict, labeldict1, block_index)
       p_nodes_block_indexes.append(exist_block_index)
      elif type(p_c.p)==list:#parent is many blocks
       for raw_p, matched_p_addrs, matched_p_asms in p_c.p:
        G, G1, labeldict, labeldict1, block_index, exist_block_index=add_node_in_graph(G, G1, appended_addr, raw_p, matched_p_addrs, matched_p_asms, labeldict, labeldict1, block_index)
        p_nodes_block_indexes.append(exist_block_index)

      #Add parents to children edge into graph
      G,G1=add_edges_in_graph(G,G1,p_nodes_block_indexes,c_nodes_block_indexes)
 draw_epilogue(G,G1,labeldict,labeldict1,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func) 

def add_edges_in_graph(G,G1,p_nodes_block_indexes,c_nodes_block_indexes):
  for p_index in p_nodes_block_indexes:
   for c_index in c_nodes_block_indexes:
    G.add_edge(p_index, c_index)
    G1.add_edge(p_index, c_index)
  return G,G1

def add_node_in_graph(G, G1, appended_addr,raw_block, matched_blk_addr, matched_blk_asm, labeldict,labeldict1,block_index):
  corresponding_block_index=-1
 #for matched_blk_addr in matched_blk_addrs:#matched blocks should have the same order as the sig block because of our agorithm.
  if matched_blk_addr not in appended_addr: #Add new node in graph
        appended_addr.append(matched_blk_addr)
        G.add_node(block_index)
        block_asm=""
        #for consecutive_insns in raw_block:
        # for insn in consecutive_insns:
        for insn in raw_block:
          if type(insn)==list:
            bp()
          block_asm+=insn+"\n"
        labeldict[block_index] = block_asm
        G1.add_node(block_index)
        block_asm1=""
        for insn in matched_blk_asm:
         block_asm1+=insn+"\n"
        labeldict1[block_index] = block_asm1
        block_index+=1#This is to record the current newest node index if a new node is to be added in the graph
        corresponding_block_index=block_index-1#This is to record the actual block index of the raw_block
  elif matched_blk_addr in appended_addr: #Find existing node index
        corresponding_block_index=appended_addr.index(matched_blk_addr)#If exists before, find the raw_block's block_index
  return G, G1, labeldict, labeldict1, block_index,corresponding_block_index

def draw_many_change(sig,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func):
 G = nx.DiGraph()#sig's graph
 G1= nx.DiGraph()#o file func's graph
 labeldict={}
 labeldict1={}
 block_index=0
 appended_addr=[]#used to record the address already in the graph. Do this do deduplicate same nodes in the graph
 for item in sig:
   new_item,matched_blk_addrs,matched_block_asms=item
   if type(new_item)==sub_p_c_sig:
     if len(new_item.p)==1:#If is single-parent connected by multiple children
       c_nodes_block_indexes=[]#record all childrens' block_index
       for c_block, matched_blk_addr, matched_blk_asm in zip(new_item.c, matched_blk_addrs[1:], matched_block_asms[1:]):
         G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, c_block, matched_blk_addr, matched_blk_asm, labeldict, labeldict1, block_index)
         c_nodes_block_indexes.append(exist_block_index)

       p_nodes_block_indexes=[]#record all parents' block_index
       G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, new_item.p[0], matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       p_nodes_block_indexes.append(exist_block_index)
       
       G,G1=add_edges_in_graph(G,G1,p_nodes_block_indexes, c_nodes_block_indexes)     
     elif len(sub_p_c.c)==1:#If is single-child connected by multiple parents
       p_nodes_block_indexes=[]#record all parents' block_index
       for p_block, matched_blk_addr, matched_blk_asm in zip(new_item.p, matched_blk_addrs[1:], matched_block_asms[1:]):
         G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, p_block, matched_blk_addr, matched_blk_asm, labeldict, labeldict1, block_index)
         p_nodes_block_indexes.append(exist_block_index)
       c_nodes_block_indexes=[]#record all childrens' block_index
       G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, new_item.c[0], matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       c_nodes_block_indexes.append(exist_block_index)
       G,G1=add_edges_in_graph(G,G1,p_nodes_block_indexes,c_nodes_block_indexes)    
   elif type(new_item)==list:
      for block,block1,asm in zip(new_item,matched_blk_addrs,matched_block_asms):
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
 draw_epilogue(G,G1,labeldict,labeldict1,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func)

def draw_one_change(sig,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func):
 G = nx.DiGraph()#sig's graph
 G1= nx.DiGraph()#o file func's graph
 labeldict={}
 labeldict1={}
 block_index=0
 appended_addr=[]#used to record the address already in the graph. Do this do deduplicate same nodes in the graph
 if len(sig)==0:#If not found matched vul insns. This is to be implemented further, but for now, we ignore it.
  return
 raw_sig,matched_blk_addrs,matched_block_asms=sig
 if len(raw_sig.p)==1:#If is single-parent connected by multiple children
       c_nodes_block_indexes=[]#record all childrens' block_index
       for c_block, matched_blk_addr, matched_block_asm in zip(raw_sig.c, matched_blk_addrs[1:], matched_block_asms[1:]):
         G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, c_block, matched_blk_addr, matched_block_asm, labeldict, labeldict1, block_index)
         c_nodes_block_indexes.append(exist_block_index)
       p_nodes_block_indexes=[]#record all parents' block_index
       G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, raw_sig.p[0], matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       p_nodes_block_indexes.append(exist_block_index)
       G,G1=add_edges_in_graph(G,G1,p_nodes_block_indexes,c_nodes_block_indexes)    
 elif len(raw_sig.c)==1:#If is single-child connected by multiple parents
       p_nodes_block_indexes=[]#record all parents' block_index
       for p_block, matched_blk_addr, matched_block_asm in zip(raw_sig.p, matched_blk_addrs[1:], matched_block_asms[1:]):
         G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, p_block, matched_blk_addr, matched_block_asm, labeldict, labeldict1, block_index)
         p_nodes_block_indexes.append(exist_block_index)
       c_nodes_block_indexes=[]#record all childrens' block_index
       G, G1, labeldict, labeldict1, block_index, exist_block_index = add_node_in_graph(G, G1, appended_addr, raw_sig.c[0], matched_blk_addrs[0], matched_block_asms[0], labeldict, labeldict1, block_index)
       c_nodes_block_indexes.append(exist_block_index)
       G,G1=add_edges_in_graph(G,G1,p_nodes_block_indexes,c_nodes_block_indexes) 
 draw_epilogue(G,G1,labeldict,labeldict1,sig_index,sim, sig_type, sig_matched_insns, sig_all_insns, selected_sig_func, selected_o_file_func)

def visualize():
 bin_sig_path=input("Please enter the bin_sig path:").strip("'")
 o_file_path=input("PLease enter the .o file path:").strip("'")
 functions_sigs=read_bin_sig(bin_sig_path)
 functions_asms,block_context_dict=process_bin(o_file_path)
 #result=match_functions_sigs_one_bin_visual(functions_sigs,functions_asms,block_context_dict)
 
 
 print("signature file contains functions:")
 i=0
 for func in functions_sigs:
  print(i,func)
  i+=1
 sig_func_index=input("Please enter the function in signature file:").strip("'")
 selected_sig_func=list(functions_sigs)[int(sig_func_index)]

 print("o file file contains functions:")
 i=0
 for func in functions_asms:
  print(i,func)
  i+=1
 o_func_index=input("Please enter the function in .o file file:").strip("'")
 selected_o_file_func=list(functions_asms)[int(o_func_index)]
 
 sig=functions_sigs[selected_sig_func]
 function_asms=functions_asms[selected_o_file_func]
 function_context=block_context_dict[selected_o_file_func]
 sim,intprt_sigs=match_one_sig_one_func_visual(sig.transformed_vul_sigs,sig.transformed_patch_sigs,sig.total_vul_insn_number,function_asms,function_context)

 draw_matched(sim,intprt_sigs,selected_sig_func,selected_o_file_func)
 

visualize()
