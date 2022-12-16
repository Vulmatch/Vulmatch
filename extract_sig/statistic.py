import os
from transform_sig import read_bin_sig
from pdb import set_trace as bp

def statistic_cwe_type():
 f_path='/home/nuc/Desktop/cve'
 f=open(f_path,'r')
 content=f.read()
 lines=content.split("\n")
 cwe_dict={}
 for line in lines:
  cwes=line.split(",")
  for cwe in cwes:
    cwe_string=cwe.strip()
    if cwe_string=="":
     continue
    if cwe_string not in cwe_dict:
     cwe_dict[cwe_string]=1
    else:
     cwe_dict[cwe_string]+=1
 total_cwe_num=0
 for cwe in cwe_dict:
  total_cwe_num+=cwe_dict[cwe]
 for cwe in cwe_dict:
  print(cwe+":"+str(cwe_dict[cwe])+" "+str(cwe_dict[cwe]*1.0/total_cwe_num))

def statistic_bin_sig():
 '''add_num=0        #add signature number
 delete_num=0     #delete signature number
 one_change_num=0 #one change signature number
 many_change_num=0#many change signature number'''

 add_sig_num_list={}#record all add signature numbers as a list
 delete_sig_num_list={}#record all delete signature numbers as a list
 one_change_sig_num_list={}#record all one_change signature numbers as a list
 many_change_sig_num_list={}#record all many_change signature numbers as a list

 
 cve_root='/home/nuc/Desktop/openjpeg_cve'
 
 cves=os.listdir(cve_root)
 for cve in cves:
  cve_path=cve_root+"/"+cve
  files=os.listdir(cve_path)
  for each in files:
    if each.startswith("bin_") and each.endswith(".pickle"):
      bin_sig_path=cve_path+"/"+each
      functions_sigs=read_bin_sig(bin_sig_path)
      for func in functions_sigs:
        sig_list=functions_sigs[func].transformed_vul_sigs
        for sig in sig_list:
          if sig.sig_type=="add":
           if cve not in add_sig_num_list:
             add_sig_num_list[cve]=[sig.insn_number]
           else:
             add_sig_num_list[cve].append(sig.insn_number)
          elif sig.sig_type=="delete":
           if cve not in delete_sig_num_list:
             delete_sig_num_list[cve]=[sig.insn_number]
           else:
             delete_sig_num_list[cve].append(sig.insn_number)
          elif sig.sig_type=="one_change":
           if cve not in one_change_sig_num_list:
             one_change_sig_num_list[cve]=[sig.insn_number]
           else:
             one_change_sig_num_list[cve].append(sig.insn_number)
          elif sig.sig_type=="many_change":
            if cve not in many_change_sig_num_list:
             many_change_sig_num_list[cve]=[sig.insn_number]
            else:
             many_change_sig_num_list[cve].append(sig.insn_number)
           
          
 print("add:")
 total=0
 sig_num=0
 for cve in add_sig_num_list:
  sig_num+=len(add_sig_num_list[cve])
  for i in add_sig_num_list[cve]:
   total+=i
 print("length:"+str(len(add_sig_num_list))+" avg size:"+str(total*1.0/len(add_sig_num_list)))
 print("sig num:",sig_num)
 print(add_sig_num_list)

 print("delete:")
 total=0
 sig_num=0
 for cve in delete_sig_num_list:
  sig_num+=len(delete_sig_num_list[cve])
  for i in delete_sig_num_list[cve]:
   total+=i
 print("length:"+str(len(delete_sig_num_list))+" avg size:"+str(total*1.0/len(delete_sig_num_list)))
 print("sig num:",sig_num)
 print(delete_sig_num_list)

 print("one_change:")
 total=0
 sig_num=0
 for cve in one_change_sig_num_list:
  sig_num+=len(one_change_sig_num_list[cve])
  for i in one_change_sig_num_list[cve]:
   total+=i
 print("length:"+str(len(one_change_sig_num_list))+" avg size:"+str(total*1.0/len(one_change_sig_num_list)))
 print("sig num:",sig_num)
 print(one_change_sig_num_list)
 
 
 print("many_change:")
 total=0
 sig_num=0
 for cve in many_change_sig_num_list:
  sig_num+=len(many_change_sig_num_list[cve])
  for i in many_change_sig_num_list[cve]:
   total+=i
 print("length:"+str(len(many_change_sig_num_list))+" avg size:"+str(total*1.0/len(many_change_sig_num_list)))
 print("sig num:",sig_num)
 print(many_change_sig_num_list)
 

#statistic_cwe_type
statistic_bin_sig()
