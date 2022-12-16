from pdb import set_trace as bp
import sys
sys.path.append('/home/nuc/Desktop/VIVA/extract_callchain_from_sourcecode/')
import pandas as pd
import os
from pattern import *
from string_util import *
all_cve_root='/home/nuc/Downloads/vulnerable_binaries/curl'

#Given a function name, we find all its caller, caller's caller, and etc. in case this f_name is inlined in one of the callers.
def find_callers(f_name,line_function_name,lines,level):
 if level==5:
  return []
 result=[]
 for line_index in range(0,len(lines)):
  if (" "+f_name+"(" in lines[line_index] or " "+f_name+" (" in lines[line_index]):
   #if f_name=="schannel_connect_common":
   # bp()
   if is_function_declaration(lines,line_index):
    continue
   if line_index not in line_function_name:#line not in dict, might be because meet itself or because some error we didn't read that line and function in the dictionary.
    continue
   if line_function_name[line_index]==f_name:#Meet it self
    continue
   caller_function=line_function_name[line_index]
   grand_pa_caller=find_callers(caller_function,line_function_name,lines,level+1)
   #print(caller_function,level)
   #if caller_function=='GetSizeParameter':
   # bp()
   result.append((caller_function,level+1))
   for f_name1 in grand_pa_caller:
    result.append(f_name1)
 result = list(dict.fromkeys(result))
 return result
 


#Divide each .c file and function name by cve index.
def read_xml(xml_path, sheet_name):
  cve_dict={}
  df=pd.read_excel(xml_path, sheet_name)
  cve_index=list(filter(None, df["CVE"]))
  file_path=list(filter(None, df["File Path"]))
  func_name=list(filter(None, df["Function Name"]))
  key=""
  for cve,f,names in zip(cve_index,file_path,func_name):
   #if cve=="CVE-2017-7468":
   # bp()
   #print(cve)
   if str(f)=="nan" or str(names)=="nan":#If we encounter lines have not enough information, skip it.
    continue
   if str(cve)!='nan':
    key=cve
    cve_dict[key]=[]
   all_name=str(names).split(",")
   funcs=[]
   for i in all_name:#Each .c file can have multiple updated functions
    if i != "nan":#WE dont append null if this line of record has only .c file with 0 function
     funcs.append(i)
   #print(key,f,funcs)
   cve_dict[key].append((f,funcs))#Each cve can have multiple updated .c files
  #for cve in cve_dict:
  # print(cve,cve_dict[cve])
  #bp()
  return cve_dict

#Find under all_cve_root/cve_index, all the paths contatining c_file in filename
def find_c_path(cve_index,c_file_name):
  print(cve_index,"c_file_name:",c_file_name)
  c_file=c_file_name.split("/")[-1]
  c_paths=[]
  cve_path=all_cve_root+"/"+str(cve_index)
  versions=os.listdir(cve_path)
  for version in versions:
   version_path=cve_path+"/"+version
   files=os.listdir(version_path)
   for each_file in files:
    if each_file==c_file:
     c_paths.append(version_path+"/"+each_file)
  #print("c_paths:",c_paths)
  return c_paths
  

def main():
 #c_path=input("Please enter the c file:")
 #line_function_name=analyze_single_c_file(c_path)
 #print(line_function_name)

 xml_path=input("Please enter the cve.xml path:").strip("'")
 sheet_name=input("Please enter the sheet name:")
 cve_dict=read_xml(xml_path, sheet_name)
 
 #f=open(c_path,'r')
 #content=delete_comments(f.read())
 #lines=content.split("\n")
 
 #result=find_callers(function,line_function_name,lines,0)
 #print(result)
 reachable_cve=os.listdir(all_cve_root)
 count=0
 all_records=0
 for i in cve_dict:
  all_records+=len(cve_dict[i])
 for cve in cve_dict:
  #if cve=="CVE-2015-3145":
  # bp()
  if cve not in reachable_cve:#For cve we can not reimplement and thus no corresponding file, just skip.
   print("No such file:",cve,"skip it...")
   continue
  for file_funcs in cve_dict[cve]:#For each .c file in the cve
   #if str(file_funcs[1])=="nan":#Have .c file but no vulnerable function record, skip it.
   # continue
   c_paths=find_c_path(cve,file_funcs[0])#contains two versions .c file paths
   for c_path in c_paths:
    version_path=c_path.split(".c")[0]
    funcs_call_result=""
    line_function_name=analyze_single_c_file_simple(c_path)
    if line_function_name=={}:
      print("analyze",c_paths,"failed!")
      call_chain_path=version_path+"_call_chain.txt"
      f=open(call_chain_path,"w")#If failed, still create a txt file for later manual fill out the file.
    
      for func in file_funcs[1]:
       funcs_call_result+=func+": [('', 1)]\n"
      f.write(funcs_call_result)
      f.close()
      continue
    f=open(c_path,'r',encoding = "ISO-8859-1")
    content=delete_comments(f.read())
    lines=content.split("\n")
    f.close() 
    call_chain_path=version_path+"_call_chain.txt"
    f=open(call_chain_path,"w")
    for func in file_funcs[1]:#For each updated function in .c file
     func_call_result=str(func)+": "
     print("find calls for:",func)
     func_call_result+=str(find_callers(func,line_function_name,lines,0))
     func_call_result+="\n"
     print(func_call_result)
     funcs_call_result+=func_call_result
   
    
    #f=open(call_chain_path,"w")
    f.write(str(funcs_call_result))
    f.close()
    count+=1
    print("finished",count,"out of",all_records)

def process_single_c_file():
 c_path=input("Please enter the c file:").strip("'")
 line_function_name=analyze_single_c_file_simple(c_path)
 print(line_function_name)
 f=open(c_path,'r')
 content=delete_comments(f.read())
 lines=content.split("\n")
 function=str(input("Please enter the function name:"))
 #print(line_function_name)
 result=find_callers(function,line_function_name,lines,0)
 print(result)

main()
#process_single_c_file()
