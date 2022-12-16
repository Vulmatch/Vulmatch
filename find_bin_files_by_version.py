import pandas as pd
import shutil
import glob
import os
from pdb import set_trace as bp
from extract_sig.common_library import find_reachable_last_vulnerable_version,find_reachable_first_patched_version 

class cve:
    def __init__(self, cve_index, last_vulnerable_version,first_patched_version,files):
        self.cve_index = cve_index
        self.last_vulnerable_version = last_vulnerable_version
        self.first_patched_version=first_patched_version
        self.files=files#This can be either source code file or binary file.

 



#Given a list of cve_index, file_path, and last_versions, we structure them by cves. The input cve_index is in form of [cve1, cve2,nan,nan,cve3...]. The input file_path is in form of [path1, path2,path3, ...pathn] with no information which paths are in a single cve. The input last_versions is in the form of [version1, version2, nan, nan, version3...].
def structurize_cve(cve_index,file_path,last_versions,descending_versions,all_compiled_versions_path):
 result_list=[]
 current_cve_begin_index=0
 current_cve_end_index=1
 while current_cve_end_index<len(cve_index):
  #print("current_cve_end_index=",current_cve_end_index)
  if str(cve_index[current_cve_end_index])=='nan':
   current_cve_end_index+=1
  else:
   last_vulnerable_version=find_reachable_last_vulnerable_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)

   first_patched_version=find_reachable_first_patched_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)
   #if str(cve_index[current_cve_begin_index])=='CVE-2016-9952':
   # bp()
   source_file,h_file=category_file_by_folder(file_path[current_cve_begin_index:current_cve_end_index])
   if last_vulnerable_version==None:#If last version not found, that means we didn't find any reachable version online, skip it.
    current_cve_end_index+=1
    continue
   
   current_cve_structure=cve(cve_index[current_cve_begin_index],last_vulnerable_version,first_patched_version,(source_file,h_file))
   print("last_vulnerable_version:",last_vulnerable_version,"wanted last version:",last_versions[current_cve_begin_index])
   result_list.append(current_cve_structure)
   current_cve_begin_index=current_cve_end_index
   current_cve_end_index+=1
 return result_list

  
#Given a list of paths of files (binary or source code), category them by the path. {path1:[bin1,bin2,...],path2:[bin1,bin2,...],...}. By default we accept format like src/xxx/xxx/xxx.c. BUt we added some exception handler in this function to deal with other cases.
def category_file_by_folder(file_paths):
 c_result_dict={}
 h_result_dict={}
 #print("category_file_by_folder")
 #print("file_paths=",file_paths)
 for each_path in file_paths:
  path=str(each_path)
  if path[0]=="/":#Reform /src/xxx/xxx/xxx.c into src/xxx/xxx/xxx.c
   path=path[1:]
  if path=="nan":
   continue
  #print("category_file_by_folder c_result_dict=",c_result_dict)
  last_slash_index=path.rfind('/')
  if last_slash_index!=-1:#Has / before .c or .h path
   parent_path=path[:last_slash_index]   
   if path[last_slash_index+1:].find(".h")!=-1:
    file_name=path[last_slash_index+1:].split(".h")[0]
    if parent_path not in h_result_dict:
     h_result_dict[parent_path]=[file_name]
    else:
     h_result_dict[parent_path].append(file_name)
   elif path[last_slash_index+1:].find(".c")==-1:
    continue
   else:
    file_name=path[last_slash_index+1:].split(".c")[0]
    if parent_path not in c_result_dict:
     c_result_dict[parent_path]=[file_name]
    else:
     c_result_dict[parent_path].append(file_name)
  else:#path is like xxx.c, no sub directory before it.
    if path.find(".c")!=-1:
     c_result_dict['']=[path.split(".c")[0]]
    elif path.find(".h")!=-1:
     h_result_dict['']=[path.split(".h")[0]]
 return c_result_dict,h_result_dict


#Find the bin file under parent_path with bin_name string as file name.
def find_bin_file_by_name(parent_path,bin_name):
  searched_files=[]
  #print("parent_path=",parent_path,"bin_name=",bin_name)
  for fname in os.listdir(parent_path):
   #print("fname=",fname,"bin_name=",bin_name_prefix)
   if bin_name in fname:
    searched_files.append(fname)
  searched_files=sorted(searched_files, key=len)
  if len(searched_files)==0:#Not found any bin with name bin_name under parent_path
   return ""
  src_path=searched_files[0]
  if parent_path.endswith("/"):
   return parent_path+src_path
  else:
   return parent_path+"/"+src_path




#Copy paste binaries for each cve to its corresponding cve folder.
def copy_paste_bin_files(cve,all_compiled_versions_path,cve_dir):
  c_files,hfiles=cve.files
  for path in c_files:
   for bin_name in c_files[path]:
    #Firstly find the .o file containing the .c file name (for last vulnerable version)
    #if path=="pngrutil.":
    # bp()
    src_path=find_bin_file_by_name(all_compiled_versions_path+"/openssl-"+cve.last_vulnerable_version+"/"+path,bin_name+".o")
    if src_path=="":#bin name not found
     print(cve.cve_index,": ",cve.last_vulnerable_version,"not found",bin_name+".o")
     continue
  
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    two_versions=os.listdir(cve_dir+"/"+cve.cve_index)
    if cve.last_vulnerable_version in two_versions:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.last_vulnerable_version
    else:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.last_vulnerable_version
     print("version not available, creating folder:",dest_path)
     os.mkdir(dest_path)
    #print("src_path=",src_path)
    #print("dest_path=",dest_path)
    shutil.copy2(src_path, dest_path)
    #bp()
    

    #Secondly find the .o file containing the .c file name (for first patched version)
    src_path=find_bin_file_by_name(all_compiled_versions_path+"/openssl-"+cve.first_patched_version+"/"+path,bin_name+".o")
    if src_path=="":#bin name not found
     print(cve.cve_index,": ",cve.first_patched_version,"not found",bin_name+".o")
     continue
  
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    two_versions=os.listdir(cve_dir+"/"+cve.cve_index)
    if cve.first_patched_version in two_versions:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.first_patched_version
    else:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.first_patched_version
     print("version not available, creating folder:",dest_path)
     os.mkdir(dest_path)
    #print("src_path=",src_path)
    #print("dest_path=",dest_path)
    shutil.copy2(src_path, dest_path)
    #bp()

def extract_bin_to_cve_folder():
 #xml_path=input("Please enter the cve.xml path:").strip("'")
 #sheet_name=input("Please enter the sheet name:")
 xml_path='/home/nuc/Downloads/vulnerable_projects/firmware/the_detailed_information_of_vulnerabilities.xlsx'
 sheet_name="dcs-6517&7517"
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
 #Now structure information for each cve 
 structured_cve_list=structurize_cve(cve_index,file_path,last_versions,descending_versions,all_compiled_versions_path)
 
 #cve_dir=input("PLease enter the folder recording all cves:").strip("'")
 cve_dir="/home/nuc/Desktop/firmware_cve/dcs-6517&7517"
 #Now copy paste bin files for each cve
 for cve in structured_cve_list:
  #print("cve=",cve.cve_index,cve.last_vulnerable_version,cve.first_patched_version,cve.files)
  copy_paste_bin_files(cve,all_compiled_versions_path,cve_dir)


def extract_source_code_to_cve_folder():
 #xml_path=input("Please enter the cve.xml path:").strip("'")
 #sheet_name=input("Please enter the sheet name:")
 xml_path="/home/nuc/Downloads/vulnerable_projects/firmware/the_detailed_information_of_vulnerabilities.xlsx"
 sheet_name="dcs-6517&7517"
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
 #Now structure information for each cve 
 structured_cve_list=structurize_cve(cve_index,file_path,last_versions,descending_versions,all_compiled_versions_path)
 #print("structured_cve_list:",structured_cve_list)
 #cve_dir=input("PLease enter the folder recording all cves:").strip("'")
 cve_dir="/home/nuc/Desktop/firmware_cve/dcs-6517&7517"
 #Now copy paste bin files for each cve
 for cve in structured_cve_list:
  #print("cve=",cve.cve_index,cve.last_vulnerable_version,cve.first_patched_version,cve.files)
  copy_paste_files(cve,all_compiled_versions_path,cve_dir)

#Copy paste binaries for each cve to its corresponding cve folder.
def copy_paste_files(cve,all_compiled_versions_path,cve_dir):
  source_files,h_files=cve.files
  for path in source_files:
   for name in source_files[path]:
     if "curl_setup." in name:
       bp()
     copy_paste_one_file(cve,name,all_compiled_versions_path,path,cve_dir,".c")
  for path in h_files:
   for name in h_files[path]:
     if "curl_setup." in name:
       bp()
     copy_paste_one_file(cve,name,all_compiled_versions_path,path,cve_dir,".h")
  
def copy_paste_one_file(cve,name,all_compiled_versions_path,path,cve_dir,suffix):
   #Firstly find the .c file containing the .c file name (for last vulnerable version)
    print("cve.last_vulnerable_version:",cve.last_vulnerable_version)
    if "curl_setup." in name:
     bp()
    src_path=find_c_file_by_name(all_compiled_versions_path+"/openssl-"+cve.last_vulnerable_version+"/"+path,name+suffix)
    
  
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    two_versions=os.listdir(cve_dir+"/"+cve.cve_index)
    if cve.last_vulnerable_version in two_versions:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.last_vulnerable_version
    else:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.last_vulnerable_version
     print("cve=",cve.cve_index,"version not available, need to creat folder:",dest_path)
     raise("version not available, need to creat folder:",dest_path)
    #print("src_path=",src_path)
    #print("dest_path=",dest_path)
    if not os.path.isfile(src_path):
     print(src_path,"not exist!")
    else:
     shutil.copy2(src_path, dest_path)
    

    #Secondly find the .c file containing the .c file name (for first patched version)
    src_path=find_c_file_by_name(all_compiled_versions_path+"/openssl-"+cve.first_patched_version+"/"+path,name+suffix)
    
  
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    two_versions=os.listdir(cve_dir+"/"+cve.cve_index)
    if cve.first_patched_version in two_versions:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.first_patched_version
    else:
     dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.first_patched_version
     print("version not available, creating folder:",dest_path)
     os.mkdir(dest_path)
    #print("src_path=",src_path)
    #print("dest_path=",dest_path)
    if not os.path.isfile(src_path):
     print(src_path,"not exist!")
    else:
     shutil.copy2(src_path, dest_path)

#Find the bin file under parent_path with bin_name string as file name.
def find_c_file_by_name(parent_path,bin_name):
  #if '/home/nuc/Downloads/vulnerable_projects/curl/curl-7.51.0/curl_setup.'==parent_path:
  # bp()
  searched_files=[]
  #print("parent_path=",parent_path,"bin_name=",bin_name)
  for fname in os.listdir(parent_path):
   #print("fname=",fname,"bin_name=",bin_name)
   if bin_name == fname:
    searched_files.append(fname)
  #searched_files=sorted(searched_files, key=len)
  try:
   src_path=searched_files[0]
  except:
   return parent_path+"/"+bin_name
  return parent_path+"/"+src_path




extract_bin_to_cve_folder()
#extract_source_code_to_cve_folder()
 
