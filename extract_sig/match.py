import os
import angr
from extract_insn_from_bin_lib import get_disasm_of_block
from transform_sig import read_bin_sig
from pdb import set_trace as bp
from common_library import increase_order
from match_library import process_bin,search_block_with_insns, search_block_context_with_context, search_block_many_change, try_find_one_sub_p_c_one_func, match_blocks_to_blocks, block_contain_consecutive_insns
import random
import pandas as pd
import shutil
#similarity_threshold=0.8#How much instructions found similar should be considered as a match
project_name="openjpeg-"

#func_sig is the transformed signature. total_sig_insn_num is the total number of insns this signature has. blocks_asm is one function's each blocks' assembly. block_context is the function's context information.
#Returns true if the candidate function is considered as vulmerable/patched.
def match_one_sig_one_func(vul_sigs,patch_sigs,total_sig_insn_num,blocks_asm,block_context):
 matched_insn_num=0#Record how many insns in the sig is matched.
 for sig,p_sig in zip(vul_sigs,patch_sigs):
  if sig.sig_type=="delete":
   tmp_matched_insn_num, dbg_matched_block_addrs=search_block_with_insns(sig.sig,blocks_asm)
   matched_insn_num+=tmp_matched_insn_num
  elif sig.sig_type=="add":
   tmp_matched_insn_num, dbg_matched_block_addrs=search_block_context_with_context(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
   print(tmp_matched_insn_num,"matched")
  elif sig.sig_type=="many_change":
   tmp_matched_insn_num, dbg_matched_block_addrs=search_block_many_change(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
  elif sig.sig_type=="one_change":
   tmp_matched_insn_num, dbg_matched_block_addrs=try_find_one_sub_p_c_one_func(sig.sig,p_sig.sig,blocks_asm,block_context)
   matched_insn_num+=tmp_matched_insn_num
 print("matched_insn_num:",matched_insn_num,"total_sig_insn_num:",total_sig_insn_num)
 sig_sim=matched_insn_num*1.0/total_sig_insn_num
 #if sig_similarity >=similarity_threshold:
 #if sig_sim>0:
 # bp()
 return sig_sim


 
def is_align_block(block_asm):
 if block_asm[0].strip().startswith("nop"):
  return True
 return False

#From a sig list of a .o file, we use each function's sig to match sigs in the binary.
def match_functions_sigs_one_bin(functions_sigs,functions_asms,block_context_dict):
  funcs_result_dict={}
  for function in functions_sigs:
   sig=functions_sigs[function]
   func_result_dict={}
   for function1 in functions_asms:
    function_asms=functions_asms[function1]
    function_context=block_context_dict[function1]
    #if function=="PKCS7_dataInit" and function1=="PKCS7_dataInit":
    # bp()
    #print(function," vs ",function1)
    if sig.total_vul_insn_number==0:
     bp()
    sim=match_one_sig_one_func(sig.transformed_vul_sigs,sig.transformed_patch_sigs,sig.total_vul_insn_number,function_asms,function_context)
    #if sim==0.46153846153846156:
    # bp()
    func_result_dict[function1]=sim
   funcs_result_dict[function]=func_result_dict
  return funcs_result_dict

def match_main():
 sig_list_path=input("Please enter the bin sig path:").strip("'")
 bin_path=input("Please enter the binary path:").strip("'")
 functions_sigs=read_bin_sig(sig_list_path)
 functions_asms,block_context_dict=process_bin(bin_path)
 result=match_functions_sigs_one_bin(functions_sigs,functions_asms,block_context_dict)
 for func in result:
  #print(func)
  max_sim=0
  max_func1=""
  for func1 in result[func]:
   print(func+" vs. "+func1+": "+str(result[func][func1]))
   if result[func][func1]>max_sim:
    max_sim=result[func][func1]
    max_func1=func1
  print("\n\n "+func+" max_sim to "+max_func1+": "+str(max_sim))
  bp()

#Find which lines in the xml belongs to the current cve
def find_current_cve_index_range(cve,cves):
 start_line=0
 end_line=0
 for index in range(0,len(cves)):
   if cves[index]==cve:
     start_line=index
     break
 for index in range(start_line+1,len(cves)):
   if type(cves[index])!=float:
     end_line=index
     break
 return start_line,end_line

#IN a list of current cve's all binary file paths, find the path that contains the file name
def find_relative_path(current_cve_file_paths,file_name):
 for path in current_cve_file_paths: 
   if type(path)==float:#skip null file path line in xml
     continue
   if path.endswith(file_name+".c"):
     return path[:path.rfind("/")]
 bp()


def match_batch():
  #xml_path=input("Please enter the cve.xml path:").strip("'")
  #sheet_name=input("Please enter the sheet name:")
  #all_versions_record=input("Please enter the path recording all versions:").strip("'")
  xml_path='/home/nuc/Desktop/VIVA/the_detailed_information_of_vulnerabilities.xlsx'
  sheet_name="openjpeg"
  all_versions_record="/home/nuc/Desktop/VIVA/openjpeg-versions"
  f=open(all_versions_record,"r")
  descending_versions=list(filter(None,f.read().split("\n")))

  #cve_path=input("Please enter cve root path:").strip("'")
  #curl_path=input("Please enter curl path:").strip("'")
  cve_path='/home/nuc/Desktop/openjpeg_cve'
  curl_path='/home/nuc/Downloads/vulnerable_projects/openjpeg'
  df=pd.read_excel(xml_path, sheet_name)
  first_versions=list(filter(None, df["First"]))
  last_versions=list(filter(None, df["Last"]))
  file_paths=list(filter(None, df["File Path"]))
  cves=list(filter(None, df["CVE"]))
  
  equal_func=0
  total_func=0
  tp=0
  dbg_string=""
  for first_v,last_v,cve in zip(first_versions,last_versions,cves):
    #if cve!="CVE-2017-12893":#For debug purpose
    # continue
    if type(first_v)==float or type(last_v)==float or type(cve)==float:
     continue
    if cve=="CVE-2018-16842" or cve=="CVE-2017-8817" or cve=="CVE-2014-0139":
     continue
    current_cve_path=cve_path+"/"+cve
    if not os.path.isdir(current_cve_path):
     continue
    files=os.listdir(current_cve_path)
    two_versions=[]
    for each in files:
     if os.path.isdir(current_cve_path+'/'+each):
       two_versions.append(each)
    two_versions=increase_order(two_versions,descending_versions)
    current_cve_start_line,current_cve_end_line=find_current_cve_index_range(cve,cves)
    current_cve_file_paths=file_paths[current_cve_start_line:current_cve_end_line]
    for each in files:
      if each.startswith("bin_") and each.endswith("_insn_sig.pickle"):  
         #if has_written_sim(cve,each):
         #  print("skip..")
         #  continue  
         bin_sig_path=current_cve_path+"/"+each
         file_name=each.replace("bin_","").replace("_insn_sig.pickle","")
         relative_path=find_relative_path(current_cve_file_paths,file_name)
         first_patch_folder=current_cve_path+"/"+two_versions[1]
         first_patch_bin_path=find_bin_with_name(first_patch_folder,file_name+".o")
         last_vul_patch_folder=current_cve_path+"/"+two_versions[0]
         last_vul_patch_bin=find_bin_with_name(last_vul_patch_folder,file_name+".o")
         random_vul_bin_path=None
         while not_well_compiled(random_vul_bin_path):
          if cve=="CVE-2015-3237" or cve=="CVE-2013-4545" or cve=="CVE-2010-0742" or cve=="CVE-2016-2179" or cve=="CVE-2016-2181" or cve=="CVE-2018-7648" or cve=="CVE-2016-10505" or cve=="CVE-2013-1447" or cve=="CVE-2017-9990" or cve=="CVE-2013-4264" or cve=="CVE-2012-2772":
           random_vul_bin_path=last_vul_patch_bin
           random_vul_version=two_versions[0]
           break
          #bp()
          print("Not well compiled",random_vul_bin_path,"cve:",cve,"each:",each,"filename:",first_patch_bin_path.split("/")[-1])
          #random_vul_version=gen_random_vul_v(first_v,two_versions[0],descending_versions,curl_path)
          random_vul_version=gen_another_vul_v(first_v,two_versions[0],descending_versions,curl_path)
          print("random_vul_version:",random_vul_version)
          #if "libpng15_la-pngrtran.o" in first_patch_bin_path:
          # bp()
          random_vul_bin_path=find_in_folder(curl_path+"/"+project_name+random_vul_version+"/"+relative_path,first_patch_bin_path.split("/")[-1],file_name)
         second_patch_version=gen_second_patch_v(two_versions[1],descending_versions,curl_path)
         second_patch_bin_path=find_in_folder(curl_path+"/"+project_name+second_patch_version+"/"+relative_path,first_patch_bin_path.split("/")[-1],file_name)
         #if random_vul_bin_path==None or last_vul_patch_bin==None or first_patch_bin_path==None or second_patch_bin_path==None:
         # bp()
         if cve=="CVE-2016-0754" or cve=="CVE-2013-4545" or cve=="CVE-2015-3197" or cve=="CVE-2018-14469" or cve=="CVE-2017-12893" or cve=="CVE-2016-10505" or cve=="CVE-2013-6053" or cve=="CVE-2011-3945":
           second_patch_bin_path=first_patch_bin_path
           second_patch_version=two_versions[1]
         #bp()
         gen_asm_eval_file(random_vul_bin_path,last_vul_patch_bin,second_patch_bin_path,random_vul_version,two_versions[0],second_patch_version)
         tmp_equal_func,tmp_total_func,dbg_string=eval_sig(random_vul_bin_path,last_vul_patch_bin,first_patch_bin_path,second_patch_bin_path,bin_sig_path,dbg_string)
         equal_func+=tmp_equal_func
         total_func+=tmp_total_func
         
         print("equal_func",equal_func,"total_func:",total_func)
  
  print("equal_func",equal_func,"total_func:",total_func)
  print(dbg_string)

#Bin not exists or can not be parsed by angr.
def not_well_compiled(random_vul_bin_path):
 if random_vul_bin_path==None:
  return True
 elif not os.path.isfile(random_vul_bin_path):
   return True
 else:
   try:
    proj=angr.Project(random_vul_bin_path,load_options={"auto_load_libs":False})
    cfg=proj.analyses.CFGFast()
   except:
    return True
 return False
 

#In the folder, find the binary file containing the name "file_name"
def find_bin_with_name(folder,file_name):
  files=os.listdir(folder)
  result_bins=[]
  for each in files:
   if file_name in each:
    result_bins.append(each)
  
  min_len=10000
  min_bin_name=""
  for each in result_bins:
   if len(each)<min_len:
    min_len=len(each)
    min_bin_name=each
  return folder+"/"+min_bin_name

def gen_random_vul_v(first_v,last_v,descending_versions,curl_path):
  max_prior_range=20
  length=0
  
  #Random generated version can not lower than this version because below it is not compilable.
  min_compiled_version="7.29.0"
  min_compiled_index=0
  for i in range(0,len(descending_versions)):
   if descending_versions[i]==min_compiled_version:
    min_compiled_index=i
  
  first_v_index=0
  for i in range(0,len(descending_versions)):
   if descending_versions[i]==first_v:
    first_v_index=i
  
  last_v_index=0
  
  for i in range(0,len(descending_versions)):
   if last_v==descending_versions[i]:
    last_v_index=i
    if i+max_prior_range>first_v_index:#We dictate first vul version to be prior 15 versions because older version may have significant compile differences, lose of funnctions etc.
     first_v_index=first_v_index
    else:
     first_v_index=i+max_prior_range
    break
  
  #for i in range(last_v_index,len(descending_versions)):
  # if first_v==descending_versions[i]:
  #   first_v_index=i
  #   break
  #Random generated version can not lower than this version because below it is not compilable.
  if first_v_index>min_compiled_index:
    first_v_index=min_compiled_index
  
  length=first_v_index-last_v_index
  
  random_v=""
  if length<=2:
   return descending_versions[first_v_index]
  while not os.path.isdir(curl_path+"/"+project_name+random_v): 
   rand=random.randint(last_v_index+1, last_v_index+length-1)
   random_index=rand
   random_v=descending_versions[random_index]
   print("No dir",curl_path+"/"+project_name+random_v,"first_v:",first_v,"last_v:",last_v)
  return random_v

def gen_another_vul_v(first_v,last_v,descending_versions,curl_path):
  min_compiled_version="7.29.0"
  first_v_index=0
  for i in range(0,len(descending_versions)):
   if descending_versions[i]==first_v:
    first_v_index=i

  min_compiled_index=0
  for i in range(0,len(descending_versions)):
   if descending_versions[i]==min_compiled_version:
    min_compiled_index=i
  for i in range(0,len(descending_versions)):
   if last_v==descending_versions[i]:
    last_v_index=i
  previous_index=last_v_index+1
  while not os.path.isdir(curl_path+"/"+project_name+descending_versions[previous_index]):
    print("No folder",curl_path+"/"+descending_versions[previous_index])
    previous_index+=1
   
  if previous_index>first_v_index:
    previous_index=first_v_index
  return descending_versions[previous_index]
  
def gen_second_patch_v(first_patch_v,descending_versions,curl_path):
 for i in range(0,len(descending_versions)):
  if descending_versions[i]==first_patch_v:
   #Find the available nearest next new version
   next_index=i-1
   while not os.path.isdir(curl_path+"/"+project_name+descending_versions[next_index]):
    print("No folder",curl_path+"/"+descending_versions[next_index])
    next_index-=1
   return descending_versions[next_index]
 
def find_in_folder(curl_path,bin_name,file_name):
 for root,dirs,files in os.walk(curl_path):
   if bin_name in files:
     return root+"/"+bin_name
 
 candidates=[]
 for root,dirs,files in os.walk(curl_path):
   for each in files:
    if file_name+".o" in each:
     candidates.append(root+"/"+each)
 min_len=10000
 min_file=""
 for each in candidates:
  if len(each)<min_len:
   min_len=len(each)
   min_file=each
 return min_file

def eval_sig(random_vul_bin_path,last_vul_patch_bin,first_patch_bin_path,second_patch_bin_path,bin_sig_path,dbg_string):
 #correct_func=0
 #wrong_func=0
 equal_func=0
 total_func=0
 functions_sigs=read_bin_sig(bin_sig_path)
 #bp()
 max_func_list0,dbg_result0=one_sig_list_one_bin(functions_sigs,random_vul_bin_path)
 max_func_list1,dbg_result1=one_sig_list_one_bin(functions_sigs,last_vul_patch_bin)
 max_func_list2,dbg_result2=one_sig_list_one_bin(functions_sigs,first_patch_bin_path)
 max_func_list3,dbg_result3=one_sig_list_one_bin(functions_sigs,second_patch_bin_path)
 for func in max_func_list0:
  total_func+=1
  if func == max_func_list0[func][0]:
   if max_func_list0[func][1]>max_func_list3[func][1]:
    dbg_string+=str(max_func_list0[func][1])+">"+str(max_func_list3[func][1])+"\n"
    #correct_func+=1
   elif max_func_list0[func][1]<max_func_list3[func][1]:
    dbg_string+=str(max_func_list0[func][1])+"<"+str(max_func_list3[func][1])+"\n"
    #wrong_func+=1
   elif max_func_list0[func][1]==max_func_list3[func][1]:
    dbg_string+=str(max_func_list0[func][1])+"=="+str(max_func_list3[func][1])+"\n"
    equal_func+=1
  else:
    dbg_string+=bin_sig_path+"  "+func+":"+str(max_func_list0[func][1])+"\n"
    #wrong_func+=1
 #bp()
 write_func_lists(random_vul_bin_path,second_patch_bin_path,max_func_list0,max_func_list3,dbg_result0,dbg_result3,'/home/nuc/Desktop/my_tool_result_version-1/'+project_name+"/"+bin_sig_path.split('/')[-2]+bin_sig_path.split('/')[-1]+".txt")
 return equal_func,total_func, dbg_string

def write_func_lists(random_vul_bin_path,second_patch_bin_path,max_func_list0,max_func_list3,func_list0,func_list3,write_path):
 f=open(write_path,'w')
 string="random_vul:"+random_vul_bin_path+"\n\nfunc_list0\n\n"+"\n max_func_list0="+str(max_func_list0)+"\n\n\n\nsecond_patch:"+second_patch_bin_path+"\n\nfunc_list3:\n\n"+"\n max_func_list3="+str(max_func_list3)
 f.write(string)
 f.close()

def has_written_sim(cve,each):
  if os.path.isfile('/home/nuc/Desktop/my_tool_result_version-1/'+project_name+"/"+cve+each+".txt"):
   return True
  return False

#Input one bin to match a bin sig .pickle. Return the first two maximum function name in bin and the similarity.
def one_sig_list_one_bin(functions_sigs,bin_path):
 max_func_list={}
 functions_asms,block_context_dict=process_bin(bin_path)
 result=match_functions_sigs_one_bin(functions_sigs,functions_asms,block_context_dict)
 for func in result:
  #print(func)
  max_sim=0
  max_func1=[]
  sorted_dict=dict(sorted(result[func].items(),key=lambda item: item[1]))
  
  max_func_list[func]=(list(sorted_dict)[-1],sorted_dict[list(sorted_dict)[-1]],list(sorted_dict)[-2],sorted_dict[list(sorted_dict)[-2]])
  '''for func1 in result[func]:
   #print(func+" vs. "+func1+": "+str(result[func][func1]))
   if result[func][func1]>max_sim:
    max_sim=result[func][func1]
    max_func1=[func1]
   #elif result[func][func1]==max_sim:
   #  max_func1.append(func1)
  max_func_list[func]=(max_func1,max_sim)'''
 return max_func_list,sorted_dict

#Copy paste all the random_vul_bin_path and second_patch_bin_path into one folder. Copy paste all the last_vul_patch_bin in another folder. 
def gen_asm_eval_file(random_vul_bin_path,last_vul_patch_bin,second_patch_bin_path,random_vul_version,last_vul_patch_bin_version,second_patch_version):
 train_path='/home/nuc/Desktop/asm2vec_version-1/'+project_name+'/train'
 test_path='/home/nuc/Desktop/asm2vec_version-1/'+project_name+'/test'
 #if not os.path.isfile(train_path+"/"+random_vul_bin_path):
 file_name=random_vul_bin_path.split('/')[-1]
 shutil.copyfile(random_vul_bin_path, train_path+"/"+random_vul_version+file_name)
 #if  not os.path.isfile(test_path+"/"+last_vul_patch_bin):
 file_name=last_vul_patch_bin.split('/')[-1]
 shutil.copyfile(last_vul_patch_bin, test_path+"/test_"+last_vul_patch_bin_version+file_name)
 #if  not os.path.isfile(train_path+"/"+second_patch_bin_path):
 file_name=second_patch_bin_path.split('/')[-1]
 if second_patch_bin_path=="":
  bp()
 shutil.copyfile(second_patch_bin_path, train_path+"/"+second_patch_version+file_name)
 

match_main()
#match_batch()
