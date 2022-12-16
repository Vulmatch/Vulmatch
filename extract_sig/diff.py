import os
from pattern import listize_lines,is_classic_function_define,extract_within_brackets,unbalanced_check
from pdb import set_trace as bp
from h_file_struct import listize_struct_lines,find_all_parent_struct_main
from struct_data_flow_analysis import extract_function_range,data_flow_main
from string_util import trim_comment
import pandas as pd
import pickle
from common_library import increase_order, func_vul_patch_signature,write_pickle,write_error,write_changed_structs,write_h_error,construct_diff_insn_list,diff_insn,structurize_cve




def diff():
 #cve_path=input("Please enter the root path for all cves:").strip("'")
 #xml_path=input("Please enter the cve.xml path:").strip("'")
 #sheet_name=input("Please enter the sheet name:")
 #xml_path="/home/nuc/Desktop/VIVA/the_detailed_information_of_vulnerabilities.xlsx"
 xml_path='/home/nuc/Downloads/vulnerable_projects/firmware/the_detailed_information_of_vulnerabilities.xlsx'
 sheet_name="dcs-6517&7517"
 cve_path="/home/nuc/Desktop/firmware_cve/dcs-6517_7517"
 df=pd.read_excel(xml_path, sheet_name)
 cve_index=list(filter(None, df["CVE"]))
 file_path=list(filter(None, df["File Path"]))
 last_versions=list(filter(None, df["Last"]))
 #all_versions_record=input("Please enter the path recording all versions:").strip("'")
 all_versions_record="/home/nuc/Desktop/VIVA/openssl-versions"
 f=open(all_versions_record,"r")
 descending_versions=list(filter(None,f.read().split("\n")))
 #all_compiled_versions_path=input("Please enter the path compiling all versions:").strip("'")
 all_compiled_versions_path='/home/nuc/Downloads/vulnerable_projects/firmware/arm_hisiv_openssls'
 funcs= list(filter(None, df["Function Name"]))
 structured_cve_list=structurize_cve(cve_index,file_path,last_versions,descending_versions,all_compiled_versions_path,funcs)

 files=os.listdir(cve_path)
 for i in files:
   #if i!='CVE-2017-12944':#For debug purpose
   #  continue
   if os.path.isdir(cve_path+"/"+i):
      current_cve_path=cve_path+"/"+i
      all_files=os.listdir(current_cve_path)
      two_versions=[]
      for index in range(0,len(all_files)):
       if os.path.isdir(current_cve_path+"/"+all_files[index]):
        two_versions.append(all_files[index])
      if len(two_versions)<2:
       bp()
      two_versions=increase_order(two_versions,descending_versions)
      version_path0=current_cve_path+"/"+two_versions[0]
      version_path1=current_cve_path+"/"+two_versions[1]
      source_files=os.listdir(version_path0)
      #changed_structs=None
      #for source_file in source_files:
      # if source_file.endswith(".h"):
      #   changed_structs=diff_h_file(i,source_file,current_cve_path,version_path0,version_path1)
      #   bp()
      for source_file in source_files:
        if source_file.endswith(".c"):
         #if i=='CVE-2013-6954':
         # bp()
         #if i!="CVE-2016-8615" or source_file!="cookie.c":#For debug purpose
         # continue
         if i=="CVE-2016-3186" or i=="CVE-2016-5102":
          continue
         diff_c_file(i,source_file,structured_cve_list,current_cve_path,version_path0,version_path1)
        

#DIff for .c files
def diff_c_file(cve,c_file,structured_cve_list,current_cve_path,version_path0,version_path1):
        function_list=extract_funcs(cve,c_file,structured_cve_list)
        c_file0=version_path0+"/"+c_file
        c_file1=version_path1+"/"+c_file
        #if cve =='CVE-2010-2249':
        # bp()
        c_line_function0=listize_lines(c_file0)
        c_line_function1=listize_lines(c_file1)
        #bp()
        diff_result=os.popen('diff '+c_file0+' '+c_file1).read()
        
        insn_signature_list,not_found_name_line,untouched_function_error=find_intersted_func_change(c_line_function0,c_line_function1,diff_result,function_list)
        #if changed_structs:
        #  write_changed_structs(current_cve_path,changed_structs)
        #  struct_signature_list=find_intersted_struct_change(c_line_function0,c_line_function1,c_file0,c_file1,function_list,changed_structs)
        #else:
        #  struct_signature_list=None
        #bp()
        write_pickle(insn_signature_list,current_cve_path,c_file)
        write_error(not_found_name_line,untouched_function_error,current_cve_path,c_file)

#Diff for .h files
def diff_h_file(cve,h_file,current_cve_path,version_path0,version_path1):
       
        h_file0=version_path0+"/"+h_file
        h_file1=version_path1+"/"+h_file
        
        h_line_function0=listize_struct_lines(h_file0)
        h_line_function1=listize_struct_lines(h_file1)
        
        diff_result=os.popen('diff '+h_file0+' '+h_file1).read()
        
        initial_structs,not_found_name_line=find_initial_struct_change(h_line_function0,h_line_function1,diff_result)
        initial_structs = list(dict.fromkeys(initial_structs))
        ancestors=[]
        #bp()
        touched_struct=[]
        for initial_struct in initial_structs:
         tmp_ancestors=find_all_parent_struct_main(h_file0,initial_struct,touched_struct)
         #bp()
         for each in tmp_ancestors:
          ancestors.append(each)
        write_h_error(not_found_name_line,current_cve_path,h_file)
        ancestors = list(dict.fromkeys(ancestors))
        return ancestors




#Find all the changed functions of a c file.
def extract_funcs(cve,c_file,structured_cve_list):
 for struct in  structured_cve_list:
  if struct.cve_index==cve:
   for path in struct.files:
     c_funcs_dict=struct.files[path]
     if c_file.split(".c")[0] in c_funcs_dict:
      return c_funcs_dict[c_file.split(".c")[0]]
 print("Error! cve and c file not found in xml!")
 bp() 


#When we diff two .c file, there are many changes in them. However, they have line number changes but without 
#specifying which function. Moreover, not all changed lines are of our interest. So we firstly find the corresponding function for each changed site, filter the non-programming changes (like comment change, string change). Then we check whether the function is of our interest.
def find_intersted_func_change(c_line_function0,c_line_function1,diff_result,function_list):
 touched_function_record={}#A dictionary recording which functions are touched. If there is any untouched function, there must be something wrong.
 for function in function_list:
  touched_function_record[function]=False
 not_found_name_line=[]
 result_list=[]
 
 diff_insn_list=construct_diff_insn_list(diff_result)
 for diff_insn in diff_insn_list:
  #if "774" in diff_insn.header:
  # bp()
  if diff_insn.header==None:
   bp()
 
  origin_lines=diff_insn.header
  function_name0=find_func_name(origin_lines[1],c_line_function0)
  function_name1=find_func_name(origin_lines[2],c_line_function1)
  #if origin_lines[2]=="905,933":
  #  bp()
  #bp()
  if function_name0!=function_name1:#If function name differs, that means an add or delete of a function, we ommit this type of signature for now.
   continue
  #if function_name0=="curl_multi_remove_handle":
  # bp()
  if function_name0=="": #Can not find function name
   not_found_name_line.append((origin_lines[1],diff_insn.origin_content))
   continue
  else:
   if function_name0 in function_list:
     touched_function_record[function_name0]=True
     if origin_lines[0]=='a': 
      #vul_sig=find_add_vul_sig()
      signature=func_vul_patch_signature(function_name0,None,diff_insn.new_content)
      result_list.append(signature)
     elif origin_lines[0]=='d':
      signature=func_vul_patch_signature(function_name0,diff_insn.origin_content,None)
      result_list.append(signature)
     elif origin_lines[0]=='c':
      signature=func_vul_patch_signature(function_name0,diff_insn.origin_content,diff_insn.new_content)
      result_list.append(signature)
 
 untouched_error=[]
 for function in touched_function_record:
  if touched_function_record[function]==False:
   untouched_error.append(function)
 return result_list,not_found_name_line,untouched_error 

#Some changes happens in the structure offsets. Thus we check from function arguments to see whether the function has any changed structure. If yes, we find all the specific-structure-related instruction as the signature.
def find_intersted_struct_change(c_line_function0,c_line_function1,c_file0,c_file1,function_list,changed_structs):
 result_list=[]
 for changed_function in function_list:
  initial_taint0=has_changed_struct(c_line_function0,c_file0,changed_function,changed_structs) 
  initial_taint1=has_changed_struct(c_line_function1,c_file1,changed_function,changed_structs) 
  if initial_taint0 and initial_taint1:#Is a change between two versions
   signature0=find_struct_signatures(c_line_function0,c_file0,changed_function,initial_taint0,changed_structs)
   signature1=find_struct_signatures(c_line_function1,c_file1,changed_function,initial_taint1,changed_structs)
   #bp()
   result_list.append(func_vul_patch_signature(changed_function,signature0,signature1))
  elif  initial_taint0 and (not initial_taint1):#New version delete it in the function argument
   signature0=find_struct_signatures(c_line_function0,c_file0,changed_function,initial_taint0,changed_structs)
   #signature1=find_struct_signatures(c_line_function1,c_file1,changed_function,[],changed_structs)
   result_list.append(func_vul_patch_signature(changed_function,signature0,None))
  elif (not initial_taint0) and initial_taint1:#New version add it in the function argument
   #signature0=find_struct_signatures(c_line_function0,c_file0,changed_function,[],changed_structs)
   signature1=find_struct_signatures(c_line_function1,c_file1,changed_function,initial_taint1,changed_structs)
   result_list.append(func_vul_patch_signature(changed_function,None,signature1))
  else:
   continue
 return result_list

   

#Check whether this version of c_file's specific function has changed struct.
def has_changed_struct(c_line_function,c_file,changed_function,changed_structs):
  f=open(c_file,'r')
  content=f.read()
  lines=content.split('\n')
  func_range=extract_function_range(c_line_function,changed_function)
  if func_range==None:#If there is no such a function in this version of source code.
   return None
  for line_index in range(func_range[0],func_range[1]):
   if is_classic_function_define(lines,line_index):
     line_string=trim_comment(lines[line_index])
     if '(' in line_string and unbalanced_check('(',line_string)==1:#Line is like func(
      arguments=extract_within_brackets(lines,line_index+1)
     elif '(' in line_string and unbalanced_check('(',line_string)==0:#Line is like func(int a, int b)
      arguments=line_string.split('(')[-1].split(')')[0]
     tainted_struct_var_name=find_struct(arguments,changed_structs)
     if len(tainted_struct_var_name)>0:
      return tainted_struct_var_name
     else:#If there is such a function in this version of source code but there is no tainted struct in argument.
      return None

#Given a string of arguments, find whether among them is a struct in changed_structs.
def find_struct(arguments,changed_structs):
 elements=arguments.split(',')
 tokens=[]
 for element in elements:
  tmp_tokens=element.split(' ')
  for tmp_token in tmp_tokens:
   tokens.append(tmp_token)
 tainted_var=[]
 for struct in changed_structs:
  if struct in tokens:
   struct_var_names=find_var_names(struct,tokens)
   for name in struct_var_names:
    tainted_var.append(name)
 return tainted_var

#THe tokens is a list of tokens from function arguments. For example: struct xxx a int b struct xxx c. For example we need to extract a if we know the struct is called xxx. 
def find_var_names(struct,tokens):
 var_names=[]
 for index in range(0,len(tokens)):
  if tokens[index]==struct:
   var_name=tokens[index+1]
   var_name=var_name.strip("*")
   var_names.append(var_name)
 return var_names
 
#Use the data flow API to slice all the relevant instructions. Note that initial_taint is a list
def find_struct_signatures(c_line_function,c_file,changed_function,initial_taint,changed_structs):
 f=open(c_file,'r')
 content=f.read()
 lines=content.split('\n')
 signatures={}
 #bp()
 #for taint in initial_taint:
 tainted_lines=data_flow_main(lines,c_line_function,initial_taint,changed_function,changed_structs)
 for tainted_line in tainted_lines:
   signatures[tainted_line]=lines[tainted_line]
 return signatures
  

#We find the initial structure that differs in two .h files and log any error.   
def find_initial_struct_change(h_line_function0,h_line_function1,diff_result):
 not_found_name_line=[]
 initial_struct=[]
 diff_insn_list=construct_diff_insn_list(diff_result)
 for diff_insn in diff_insn_list:
  if diff_insn.header==None:
   bp()
  origin_lines=diff_insn.header
  struct_name=find_struct_name(origin_lines[1],h_line_function0)
  if struct_name=="": #Can not find function name
   not_found_name_line.append((origin_lines[1],diff_insn.origin_content))
   continue
  else:
   initial_struct.append(struct_name)  
 return initial_struct,not_found_name_line

#Find out what function the change lines points to.
def find_func_name(origin_lines,c_line_function):
 if origin_lines.find(',')!=-1:#If the diff line is like 123,156 which means a range of changed lines
  start_line= int(origin_lines.split(",")[0])
  end_line=int(origin_lines.split(",")[1])
  for line in range(start_line,end_line+1):
   if line in c_line_function:
    return c_line_function[line]
 else:#If the diff is like 123 which means that only line 123 is changed.
  line=int(origin_lines)
  if line not in c_line_function:
   return ""
  return c_line_function[line]
 return ""

#Find out what struct the change lines points to
def find_struct_name(origin_lines,h_line_function):
 if origin_lines.find(',')!=-1:#If the diff line is like 123,156 which means a range of changed lines
  start_line= int(origin_lines.split(",")[0])
  end_line=int(origin_lines.split(",")[1])
  for line in range(start_line,end_line+1):
   if line in h_line_function:
    return h_line_function[line]  
 else:#If the diff is like 123 which means that only line 123 is changed.
  line=int(origin_lines)
  if line not in h_line_function:
   return ""
  return h_line_function[line]
 return "" 
  



diff()
        
