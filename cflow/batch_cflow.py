import os
import pandas as pd
all_cve_root='/home/nuc/Downloads/vulnerable_binaries/curl'

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

#Automatically execute cflow on all .c files
def auto_cflow():
 xml_path=input("Please enter the cve.xml path:").strip("'")
 sheet_name=input("Please enter the sheet name:")
 cve_dict=read_xml(xml_path, sheet_name)

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
    print(c_path)
    cflow_path=c_path.replace(".c","_cflow.txt")
    os.system("cflow "+c_path+" > "+cflow_path)

auto_cflow()
